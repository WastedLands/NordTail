// Package wgconf parses provider-generated wg-quick configurations into a
// tunnel definition (DESIGN.md provider "wgconf").
package wgconf

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/WastedLands/NordTail/internal/secret"
)

// Tunnel is everything needed to bring up one region's WireGuard interface.
// It holds the private key, so it must never be logged or serialized; the
// key is a secret.String for that reason.
type Tunnel struct {
	PrivateKey   secret.String
	Addresses    []netip.Prefix
	DNS          []netip.Addr
	MTU          int
	PeerKey      wgtypes.Key
	PresharedKey secret.String
	Endpoint     string // host:port; host may be a name, resolved at apply time
	AllowedIPs   []netip.Prefix
	Keepalive    time.Duration
}

// Parse validates a wg-quick config. Script hooks (PreUp, PostUp, ...) and
// wg-quick-only keys are ignored, never executed. The config must route all
// IPv4 traffic (0.0.0.0/0) through exactly one peer.
func Parse(text string) (*Tunnel, error) {
	t := &Tunnel{}
	section := ""
	peers := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	for line := 1; sc.Scan(); line++ {
		l := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = strings.ToLower(strings.TrimSpace(l[1 : len(l)-1]))
			if section == "peer" {
				peers++
			}
			if section != "interface" && section != "peer" {
				return nil, fmt.Errorf("line %d: unknown section [%s]", line, section)
			}
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", line)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if err := t.set(section, k, v); err != nil {
			return nil, fmt.Errorf("line %d: %s: %w", line, k, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	switch {
	case peers != 1:
		return nil, fmt.Errorf("want exactly one [Peer], got %d", peers)
	case t.PrivateKey.IsZero():
		return nil, errors.New("[Interface] PrivateKey is required")
	case len(t.Addresses) == 0:
		return nil, errors.New("[Interface] Address is required")
	case t.PeerKey == (wgtypes.Key{}):
		return nil, errors.New("[Peer] PublicKey is required")
	case t.Endpoint == "":
		return nil, errors.New("[Peer] Endpoint is required")
	}
	if !containsPrefix(t.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0")) {
		return nil, errors.New("[Peer] AllowedIPs must include 0.0.0.0/0 to carry exit traffic")
	}
	return t, nil
}

func (t *Tunnel) set(section, k, v string) error {
	switch section + "." + k {
	case "interface.privatekey":
		if _, err := wgtypes.ParseKey(v); err != nil {
			return errors.New("not a WireGuard key")
		}
		t.PrivateKey = secret.New(v)
	case "interface.address":
		ps, err := prefixes(v, true)
		if err != nil {
			return err
		}
		t.Addresses = append(t.Addresses, ps...)
	case "interface.dns":
		for _, f := range splitList(v) {
			a, err := netip.ParseAddr(f)
			if err != nil {
				// wg-quick also accepts search domains here; NordTail
				// only needs resolver addresses.
				continue
			}
			t.DNS = append(t.DNS, a)
		}
	case "interface.mtu":
		n, err := strconv.Atoi(v)
		if err != nil || n < 1280 || n > 9000 {
			return errors.New("must be 1280-9000")
		}
		t.MTU = n
	case "peer.publickey":
		key, err := wgtypes.ParseKey(v)
		if err != nil {
			return errors.New("not a WireGuard key")
		}
		t.PeerKey = key
	case "peer.presharedkey":
		if _, err := wgtypes.ParseKey(v); err != nil {
			return errors.New("not a WireGuard key")
		}
		t.PresharedKey = secret.New(v)
	case "peer.endpoint":
		host, port, ok := strings.Cut(v, ":")
		if strings.HasPrefix(v, "[") {
			ap, err := netip.ParseAddrPort(v)
			if err != nil {
				return err
			}
			host, port, ok = ap.Addr().String(), strconv.Itoa(int(ap.Port())), true
		}
		if !ok || host == "" {
			return errors.New("want host:port")
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return errors.New("invalid port")
		}
		t.Endpoint = v
	case "peer.allowedips":
		ps, err := prefixes(v, false)
		if err != nil {
			return err
		}
		t.AllowedIPs = append(t.AllowedIPs, ps...)
	case "peer.persistentkeepalive":
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return errors.New("invalid seconds")
		}
		t.Keepalive = time.Duration(n) * time.Second
	case "interface.listenport", "interface.fwmark", "interface.table", "interface.saveconfig",
		"interface.preup", "interface.postup", "interface.predown", "interface.postdown":
		// wg-quick-only or script hooks: ignored on purpose.
	default:
		if section == "" {
			return errors.New("key outside any section")
		}
		return errors.New("unknown key")
	}
	return nil
}

func prefixes(v string, hostAddr bool) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range splitList(v) {
		var p netip.Prefix
		var err error
		if strings.Contains(f, "/") {
			p, err = netip.ParsePrefix(f)
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(f)
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", f)
		}
		if !hostAddr {
			p = p.Masked()
		}
		out = append(out, p)
	}
	return out, nil
}

func splitList(v string) []string {
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func containsPrefix(ps []netip.Prefix, want netip.Prefix) bool {
	for _, p := range ps {
		if p == want {
			return true
		}
	}
	return false
}
