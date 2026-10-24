//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// Checks run in source order against the shared environment from TestMain.
// Destructive checks (restart, tunnel down) come last and restore state.

func TestEgressIP(t *testing.T) {
	useExitNode(t)
	n := nonce("egress")
	body, err := clientExec("curl", "-sS", "-m", "10", "http://"+addrEcho+"/"+n)
	srcs := echoSources(t, n)
	ok := err == nil && strings.TrimSpace(body) == addrVPN && allEqual(srcs, addrVPN)
	check(t, "egress_ip", []int{1}, addrVPN, fmt.Sprintf("body=%q echo_sources=%v", body, srcs), ok, errDetail(err))
}

func TestDirectPath(t *testing.T) {
	useExitNode(t)
	out, _ := clientExec("tailscale", "ping", "-c", "10", "--until-direct", regionHost)
	ok := strings.Contains(out, "via "+addrNordTail+":") && !strings.Contains(lastLine(out), "DERP")
	check(t, "direct_path", []int{5}, "pong via "+addrNordTail+":<port>", lastLine(out), ok, "")
}

func TestDNSViaTunnel(t *testing.T) {
	useExitNode(t)
	n := nonce("dns")
	out, err := clientExec("dig", "+short", "+time=5", "+tries=2", "@100.100.100.100", "TXT", n+".whoami.test")
	srcs := echoDNSSources(t, n)
	ok := err == nil && strings.Contains(out, `"`+addrVPN+`"`) && allEqual(srcs, addrVPN)
	check(t, "dns_via_tunnel", []int{3}, "TXT "+addrVPN+", queries only from "+addrVPN,
		fmt.Sprintf("answer=%q echo_sources=%v", out, srcs), ok, errDetail(err))
}

func TestDashboardAuthz(t *testing.T) {
	admin, aerr := api("client", "GET", "/api/v1/whoami", "")
	_, oerr := api("outsider", "GET", "/api/v1/whoami", "")
	ok := aerr == nil && strings.Contains(admin, `"admin":true`) &&
		oerr != nil && strings.Contains(oerr.Error(), "HTTP 403")
	check(t, "dashboard_authz_allowlist", []int{8}, "admin 200 admin=true, outsider 403",
		fmt.Sprintf("admin=%q outsider_err=%v", admin, oerr), ok, errDetail(aerr))
}

func TestListeners(t *testing.T) {
	// Container netns: no TCP listener reachable from the host network.
	outer, err := run("docker", "run", "--rm", "--net", "container:"+project+"-nordtail-1", project+"-client",
		"ss", "-Htln")
	var bad []string
	for _, l := range listenAddrs(outer) {
		if !loopback(l) {
			bad = append(bad, "container:"+l)
		}
	}
	// Region netns: TCP listeners only on tailnet or loopback addresses.
	inner, ierr := regionExec("ss", "-Htln")
	for _, l := range listenAddrs(inner) {
		if !loopback(l) && !tailnetAddr(l) {
			bad = append(bad, "region:"+l)
		}
	}
	ok := err == nil && ierr == nil && len(bad) == 0
	check(t, "listeners", []int{9}, "no TCP listener outside loopback/tailnet addresses",
		fmt.Sprintf("offending=%v", bad), ok, errDetail(err)+errDetail(ierr))
}

func TestRestartIdentity(t *testing.T) {
	before, err := exitNode(t)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := compose("--profile", "nordtail", "restart", "nordtail"); err != nil {
		t.Fatalf("restart: %v\n%s", err, out)
	}
	rerr := waitFor(120*time.Second, regionReady)
	after, err := exitNode(t)
	dupes := countNodes(t, regionHost)
	ok := rerr == nil && err == nil && before.ID == after.ID && before.GivenName == after.GivenName &&
		slices.Equal(before.IPs, after.IPs) && dupes == 1
	check(t, "restart_identity", []int{6}, fmt.Sprintf("%+v, 1 node named %s", before, regionHost),
		fmt.Sprintf("%+v, %d nodes", after, dupes), ok, errDetail(rerr))
}

func TestLeakTunnelDown(t *testing.T) {
	t.Run("peer_unreachable", func(t *testing.T) {
		useExitNode(t)
		if out, err := compose("stop", "fakevpn"); err != nil {
			t.Fatalf("stop fakevpn: %v\n%s", err, out)
		}
		defer restoreFakeVPN(t)
		n := nonce("leak-peer")
		_, cerr := clientExec("curl", "-sS", "-m", "8", "http://"+addrEcho+"/"+n)
		_, _ = clientExec("dig", "+short", "+time=3", "+tries=1", "@100.100.100.100", "TXT", n+".whoami.test")
		srcs := append(echoSources(t, n), echoDNSSources(t, n)...)
		// The VPN is gone, so nothing can arrive through it either.
		check(t, "leak_tunnel_down", []int{2}, "request fails, echo sees nothing",
			fmt.Sprintf("curl_err=%v echo_sources=%v", cerr != nil, srcs), cerr != nil && len(srcs) == 0, "")

		// Past the grace period the node goes offline (decision 0004). The
		// client must stay blocked rather than fall back to its own uplink.
		before, err := exitNode(t)
		if err != nil {
			t.Fatal(err)
		}
		werr := waitFor(downGrace+30*time.Second, func() error {
			if n, err := exitNode(t); err != nil || n.Online {
				return fmt.Errorf("still online: %+v %v", n, err)
			}
			return nil
		})
		n2 := nonce("withdrawn")
		_, cerr2 := clientExec("curl", "-sS", "-m", "8", "http://"+addrEcho+"/"+n2)
		srcs2 := echoSources(t, n2)
		restoreFakeVPN(t)
		after, aerr := exitNode(t)
		ok := werr == nil && cerr2 != nil && len(srcs2) == 0 && aerr == nil && after.Online && after.ID == before.ID
		check(t, "withdraw_offline", []int{12}, "offline after grace, client blocked, same node back online",
			fmt.Sprintf("went_offline=%v curl_err=%v echo_sources=%v back=%+v", werr == nil, cerr2 != nil, srcs2, after),
			ok, errDetail(werr)+errDetail(aerr))
	})
	t.Run("wg_link_down", func(t *testing.T) {
		useExitNode(t)
		if out, err := regionExec("ip", "link", "set", "wg-"+regionID, "down"); err != nil {
			t.Fatalf("link down: %v\n%s", err, out)
		}
		defer restoreNordTail(t)
		n := nonce("leak-link")
		start := time.Now()
		_, cerr := clientExec("curl", "-sS", "-m", "8", "http://"+addrEcho+"/"+n)
		took := time.Since(start).Round(100 * time.Millisecond)
		dns, _ := clientExec("dig", "+short", "+time=3", "+tries=1", "@100.100.100.100", "TXT", n+".whoami.test")
		srcs := append(echoSources(t, n), echoDNSSources(t, n)...)
		// A controller may repair the link quickly, so tunneled arrivals are
		// fine; any other source is a leak.
		check(t, "leak_link_down", []int{2}, "nothing reaches echo except via the VPN",
			fmt.Sprintf("curl_err=%v took=%s echo_sources=%v", cerr != nil, took, srcs), onlyFrom(srcs, addrVPN), "")
		check(t, "dns_link_down", []int{3}, "no answer except via the VPN",
			fmt.Sprintf("answer=%q", dns), dns == "" || strings.Contains(dns, `"`+addrVPN+`"`), "")
	})
}

// ---- helpers ----

func useExitNode(t *testing.T) {
	t.Helper()
	if out, err := clientExec("tailscale", "set", "--exit-node="+regionHost); err != nil {
		t.Fatalf("select exit node: %v\n%s", err, out)
	}
}

// regionExec runs a command inside the region netns of the NordTail container
// (iproute2-style /var/run/netns/rg-<id>, entered through PID 1's mount ns).
func regionExec(args ...string) (string, error) {
	base := []string{"run", "--rm", "--privileged", "--pid", "container:" + project + "-nordtail-1", project + "-client",
		"nsenter", "-t", "1", "-m", "-n", "--", "ip", "netns", "exec", "rg-" + regionID}
	return run("docker", append(base, args...)...)
}

func restoreFakeVPN(t *testing.T) {
	t.Helper()
	if out, err := compose("start", "fakevpn"); err != nil {
		t.Fatalf("start fakevpn: %v\n%s", err, out)
	}
	if err := waitFor(90*time.Second, func() error {
		body, err := clientExec("curl", "-sS", "-m", "5", "http://"+addrEcho+"/restore")
		if err != nil || strings.TrimSpace(body) != addrVPN {
			return fmt.Errorf("egress not restored: %q %v", body, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func restoreNordTail(t *testing.T) {
	t.Helper()
	if out, err := compose("--profile", "nordtail", "restart", "nordtail"); err != nil {
		t.Fatalf("restart nordtail: %v\n%s", err, out)
	}
	if err := waitFor(120*time.Second, regionReady); err != nil {
		t.Fatal(err)
	}
}

type echoEvent struct {
	Proto string `json:"proto"`
	Src   string `json:"src"`
	Path  string `json:"path"`
	QName string `json:"qname"`
}

func echoEvents(t *testing.T) []echoEvent {
	t.Helper()
	time.Sleep(500 * time.Millisecond) // let the echo log flush
	out, err := compose("logs", "--no-log-prefix", "--no-color", "echo")
	if err != nil {
		t.Fatalf("echo logs: %v", err)
	}
	var evs []echoEvent
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		var e echoEvent
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Proto != "" {
			evs = append(evs, e)
		}
	}
	return evs
}

func echoSources(t *testing.T, n string) []string {
	var s []string
	for _, e := range echoEvents(t) {
		if e.Proto == "http" && strings.Contains(e.Path, n) {
			s = append(s, e.Src)
		}
	}
	return s
}

func echoDNSSources(t *testing.T, n string) []string {
	var s []string
	for _, e := range echoEvents(t) {
		if e.Proto == "dns" && strings.HasPrefix(e.QName, n) {
			s = append(s, e.Src)
		}
	}
	return s
}

type hsNode struct {
	ID        uint64
	GivenName string
	IPs       []string
	Online    bool
}

func headscaleNodes(t *testing.T) []hsNode {
	t.Helper()
	out, err := headscale("nodes", "list", "-o", "json")
	if err != nil {
		t.Fatalf("headscale nodes list: %v\n%s", err, out)
	}
	var raw []struct {
		ID          uint64   `json:"id"`
		GivenName   string   `json:"given_name"`
		IPAddresses []string `json:"ip_addresses"`
		Online      bool     `json:"online"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("nodes JSON: %v", err)
	}
	var ns []hsNode
	for _, r := range raw {
		ns = append(ns, hsNode{ID: r.ID, GivenName: r.GivenName, IPs: r.IPAddresses, Online: r.Online})
	}
	return ns
}

func exitNode(t *testing.T) (hsNode, error) {
	for _, n := range headscaleNodes(t) {
		if n.GivenName == regionHost {
			return n, nil
		}
	}
	return hsNode{}, fmt.Errorf("no node named %s in headscale", regionHost)
}

func countNodes(t *testing.T, prefix string) int {
	c := 0
	for _, n := range headscaleNodes(t) {
		if strings.HasPrefix(n.GivenName, prefix) {
			c++
		}
	}
	return c
}

// listenAddrs extracts local addresses (without port) from `ss -Htln` output.
func listenAddrs(ss string) []string {
	var as []string
	for _, l := range strings.Split(ss, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		a := f[3]
		if i := strings.LastIndexByte(a, ':'); i > 0 {
			a = a[:i]
		}
		as = append(as, strings.Trim(a, "[]"))
	}
	return as
}

func loopback(a string) bool {
	return strings.HasPrefix(a, "127.") || a == "::1"
}

func tailnetAddr(a string) bool {
	if strings.HasPrefix(a, "fd7a:115c:a1e0:") {
		return true
	}
	var b1, b2 int
	if _, err := fmt.Sscanf(a, "%d.%d.", &b1, &b2); err == nil {
		return b1 == 100 && b2 >= 64 && b2 <= 127
	}
	return false
}

// onlyFrom reports whether every source is want (vacuously true when empty).
func onlyFrom(ss []string, want string) bool {
	for _, s := range ss {
		if s != want {
			return false
		}
	}
	return true
}

func allEqual(ss []string, want string) bool {
	if len(ss) == 0 {
		return false
	}
	for _, s := range ss {
		if s != want {
			return false
		}
	}
	return true
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func errDetail(err error) string {
	if err == nil {
		return ""
	}
	return " err=" + err.Error()
}
