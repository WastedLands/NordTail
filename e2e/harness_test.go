//go:build e2e

// Package e2e is NordTail's hermetic end-to-end suite. It drives the Docker
// Compose environment in compose.yaml: Headscale as the coordination server,
// a WireGuard "fake VPN", an echo service standing in for the internet, test
// clients, and the NordTail container under test.
//
// Run with `make e2e`. Set E2E_KEEP=1 to leave the environment running.
package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Fixed harness addresses (see compose.yaml).
const (
	addrEcho     = "203.0.113.20"
	addrVPN      = "203.0.113.30" // fake VPN egress: tunneled traffic shows this source
	addrClient   = "203.0.113.40" // traffic that bypassed the exit node
	addrNordTail = "203.0.113.50" // traffic that leaked out of the NordTail host
	addrEchoV6   = "2001:db8:30::20"

	regionID   = "test"
	regionHost = "exit-test"
	dashboard  = "http://nordtail.e2e.test"
	loginURL   = "http://headscale:8080"

	// Short tunnel-down grace period so the withdrawal check runs quickly.
	downGrace = 5 * time.Second
)

var (
	project = "nordtail-e2e"
	outDir  string
	env     *harness
)

type harness struct {
	tagKey     string // reusable, tagged tag:nordtail
	adminKey   string // reusable, user admin
	outsideKey string // reusable, user outsider
	regionPriv wgtypes.Key
	vpnPriv    wgtypes.Key
}

func TestMain(m *testing.M) {
	wd, _ := os.Getwd()
	outDir = filepath.Join(wd, "out")
	report.Started = time.Now().UTC()
	report.Control = "headscale"

	code := 1
	if err := setup(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e setup failed: %v\n", err)
		report.SetupError = err.Error()
		dumpLogs()
	} else {
		code = m.Run()
		if code != 0 {
			dumpLogs()
		}
	}
	report.Finished = time.Now().UTC()
	if err := report.write(filepath.Join(outDir, "report.json")); err != nil {
		fmt.Fprintf(os.Stderr, "writing report: %v\n", err)
	}
	if os.Getenv("E2E_KEEP") == "" {
		_, _ = compose("--profile", "nordtail", "down", "-v", "--remove-orphans")
	}
	os.Exit(code)
}

func setup() error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	h := &harness{}
	var err error
	if h.regionPriv, err = wgtypes.GeneratePrivateKey(); err != nil {
		return err
	}
	if h.vpnPriv, err = wgtypes.GeneratePrivateKey(); err != nil {
		return err
	}
	if err := writeEnv("fakevpn.env", map[string]string{
		"FAKEVPN_PRIVATE_KEY":     h.vpnPriv.String(),
		"FAKEVPN_PEER_PUBLIC_KEY": h.regionPriv.PublicKey().String(),
		"FAKEVPN_PEER_ADDRESS":    "10.99.0.2/32",
	}); err != nil {
		return err
	}
	// nordtail.env must exist for `compose up` of the infra services too.
	if err := writeEnv("nordtail.env", map[string]string{}); err != nil {
		return err
	}

	_, _ = compose("--profile", "nordtail", "down", "-v", "--remove-orphans")
	if out, err := compose("up", "-d", "--build", "headscale", "derp", "echo", "fakevpn", "client", "outsider"); err != nil {
		return fmt.Errorf("compose up infra: %v\n%s", err, out)
	}
	if err := waitFor(30*time.Second, func() error {
		_, err := headscale("users", "list")
		return err
	}); err != nil {
		return fmt.Errorf("headscale not ready: %w", err)
	}
	for _, u := range []string{"admin", "outsider"} {
		if out, err := headscale("users", "create", u); err != nil {
			return fmt.Errorf("create user %s: %v\n%s", u, err, out)
		}
	}
	if h.tagKey, err = preauthKey(1, "tag:nordtail"); err != nil {
		return err
	}
	if h.adminKey, err = preauthKey(1, ""); err != nil {
		return err
	}
	if h.outsideKey, err = preauthKey(2, ""); err != nil {
		return err
	}
	for svc, key := range map[string]string{"client": h.adminKey, "outsider": h.outsideKey} {
		if out, err := tsUp(svc, key); err != nil {
			return fmt.Errorf("tailscale up on %s: %v\n%s", svc, err, out)
		}
	}

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return err
	}
	if err := writeEnv("nordtail.env", map[string]string{
		"NORDTAIL_MASTER_KEY":   base64.StdEncoding.EncodeToString(masterKey),
		"NORDTAIL_TS_AUTHKEY":   h.tagKey,
		"NORDTAIL_LOGIN_SERVER": loginURL,
		"NORDTAIL_DOWN_GRACE":   downGrace.String(),
		"NORDTAIL_ADMINS":       "admin", // Headscale users appear in WhoIs by bare name
	}); err != nil {
		return err
	}
	if out, err := compose("--profile", "nordtail", "up", "-d", "--build", "nordtail"); err != nil {
		return fmt.Errorf("compose up nordtail: %v\n%s", err, out)
	}
	if err := waitFor(90*time.Second, func() error {
		_, err := api("client", "GET", "/api/v1/whoami", "")
		return err
	}); err != nil {
		return fmt.Errorf("dashboard not reachable from the tailnet: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"id": regionID, "provider": "wgconf", "wgconf": h.wgconf()})
	if out, err := api("client", "POST", "/api/v1/regions", string(body)); err != nil {
		return fmt.Errorf("create region: %v\n%s", err, out)
	}
	if err := waitFor(90*time.Second, regionReady); err != nil {
		return fmt.Errorf("region %s never became ready: %w", regionID, err)
	}
	if err := warmPaths(); err != nil {
		return err
	}
	env = h
	return nil
}

// warmPaths establishes direct paths from the client to the dashboard and the
// exit node. The harness has no relay, so the first packets to a peer can
// stall until disco finds the direct path.
func warmPaths() error {
	for _, peer := range []string{"nordtail", regionHost} {
		if out, err := clientExec("tailscale", "ping", "-c", "20", "--until-direct", peer); err != nil {
			return fmt.Errorf("no direct path to %s: %v\n%s", peer, err, out)
		}
	}
	return nil
}

func (h *harness) wgconf() string {
	return strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + h.regionPriv.String(),
		"Address = 10.99.0.2/32",
		"DNS = " + addrEcho,
		"",
		"[Peer]",
		"PublicKey = " + h.vpnPriv.PublicKey().String(),
		"Endpoint = " + addrVPN + ":51820",
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"PersistentKeepalive = 25",
		"",
	}, "\n")
}

// regionReady reports nil once the region's tunnel is up and its exit node is
// approved and offered to the test client.
func regionReady() error {
	out, err := api("client", "GET", "/api/v1/regions/"+regionID, "")
	if err != nil {
		return err
	}
	var r struct {
		Tunnel struct{ Up bool } `json:"tunnel"`
		Node   struct {
			Online       bool `json:"online"`
			ExitApproved bool `json:"exit_approved"`
		} `json:"node"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return fmt.Errorf("region JSON: %v: %s", err, out)
	}
	if !r.Tunnel.Up || !r.Node.Online || !r.Node.ExitApproved {
		return fmt.Errorf("not ready: %s", out)
	}
	st, err := clientExec("tailscale", "status", "--json")
	if err != nil {
		return err
	}
	if !strings.Contains(st, `"HostName": "`+regionHost+`"`) {
		return fmt.Errorf("client does not see %s yet", regionHost)
	}
	return nil
}

// ---- process helpers ----

func compose(args ...string) (string, error) {
	return run("docker", append([]string{"compose", "-p", project, "-f", "compose.yaml"}, args...)...)
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return strings.TrimSpace(buf.String()), err
}

func execIn(svc string, args ...string) (string, error) {
	return compose(append([]string{"exec", "-T", svc}, args...)...)
}

func clientExec(args ...string) (string, error) { return execIn("client", args...) }

func headscale(args ...string) (string, error) {
	return execIn("headscale", append([]string{"headscale"}, args...)...)
}

func preauthKey(user int, tags string) (string, error) {
	args := []string{"preauthkeys", "create", "--user", fmt.Sprint(user), "--reusable", "-o", "json"}
	if tags != "" {
		args = append(args, "--tags", tags)
	}
	out, err := headscale(args...)
	if err != nil {
		return "", fmt.Errorf("preauthkeys create: %v\n%s", err, out)
	}
	var k struct{ Key string }
	if err := json.Unmarshal([]byte(out), &k); err != nil || k.Key == "" {
		return "", fmt.Errorf("preauthkeys output: %q", out)
	}
	return k.Key, nil
}

func tsUp(svc, key string) (string, error) {
	return execIn(svc, "tailscale", "up", "--login-server", loginURL, "--auth-key", key, "--hostname", svc, "--timeout", "60s")
}

// api calls the NordTail dashboard API from inside a tailnet client container
// and returns the body. Non-2xx responses are errors that carry the status.
func api(svc, method, path, body string) (string, error) {
	args := []string{"curl", "-sS", "-m", "15", "-X", method, "-w", "\n%{http_code}"}
	if body != "" {
		args = append(args, "-H", "Content-Type: application/json", "--data-binary", body)
	}
	out, err := execIn(svc, append(args, dashboard+path)...)
	if err != nil {
		return out, err
	}
	i := strings.LastIndexByte(out, '\n')
	if i < 0 {
		return out, fmt.Errorf("no status in curl output: %q", out)
	}
	resp, code := out[:i], out[i+1:]
	if !strings.HasPrefix(code, "2") {
		return resp, fmt.Errorf("HTTP %s: %s", code, resp)
	}
	return resp, nil
}

func writeEnv(name string, kv map[string]string) error {
	var b strings.Builder
	for k, v := range kv {
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	return os.WriteFile(filepath.Join(outDir, name), []byte(b.String()), 0o600)
}

func waitFor(d time.Duration, f func() error) error {
	deadline := time.Now().Add(d)
	var err error
	for time.Now().Before(deadline) {
		if err = f(); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return err
}

func dumpLogs() {
	out, _ := compose("--profile", "nordtail", "logs", "--no-color", "--tail", "60")
	_ = os.WriteFile(filepath.Join(outDir, "compose.log"), []byte(out), 0o600)
	fmt.Fprintf(os.Stderr, "compose logs written to %s\n", filepath.Join(outDir, "compose.log"))
}

func nonce(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%x", prefix, b)
}
