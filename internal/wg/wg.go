// Package wg creates and inspects region WireGuard interfaces.
package wg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/WastedLands/NordTail/internal/netns"
	"github.com/WastedLands/NordTail/internal/provider/wgconf"
)

const defaultKeepalive = 25 * time.Second

// Create builds the interface in the container netns, configures it, and
// moves it into the region netns, where it gets its addresses and comes up.
// Its UDP socket stays in the container netns, so encrypted traffic never
// depends on region routing (decision 0003).
func Create(ctx context.Context, outer *netns.Outer, region vnetns.NsHandle, name string, t *wgconf.Tunnel) error {
	endpoint, err := resolveEndpoint(ctx, t.Endpoint)
	if err != nil {
		return err
	}
	priv, err := wgtypes.ParseKey(t.PrivateKey.Reveal())
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	ka := t.Keepalive
	if ka == 0 {
		ka = defaultKeepalive // the health check relies on regular handshakes
	}
	peer := wgtypes.PeerConfig{
		PublicKey:                   t.PeerKey,
		Endpoint:                    endpoint,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  ipnets(t.AllowedIPs),
		PersistentKeepaliveInterval: &ka,
	}
	if !t.PresharedKey.IsZero() {
		psk, err := wgtypes.ParseKey(t.PresharedKey.Reveal())
		if err != nil {
			return fmt.Errorf("preshared key: %w", err)
		}
		peer.PresharedKey = &psk
	}
	mtu := t.MTU
	if mtu == 0 {
		mtu = 1420
	}

	err = netns.InNS(outer.NS, func() error {
		if old, err := netlink.LinkByName(name); err == nil {
			_ = netlink.LinkDel(old)
		}
		la := netlink.NewLinkAttrs()
		la.Name, la.MTU = name, mtu
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la}); err != nil {
			return fmt.Errorf("add %s: %w", name, err)
		}
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer c.Close()
		if err := c.ConfigureDevice(name, wgtypes.Config{PrivateKey: &priv, ReplacePeers: true, Peers: []wgtypes.PeerConfig{peer}}); err != nil {
			return fmt.Errorf("configure %s: %w", name, err)
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		return netlink.LinkSetNsFd(link, int(region))
	})
	if err != nil {
		return err
	}

	h, err := netlink.NewHandleAt(region)
	if err != nil {
		return err
	}
	defer h.Close()
	link, err := h.LinkByName(name)
	if err != nil {
		return err
	}
	for _, p := range t.Addresses {
		if !p.Addr().Is4() {
			continue // no IPv6 through the tunnel yet
		}
		a := &netlink.Addr{IPNet: &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), 32)}}
		if err := h.AddrAdd(link, a); err != nil {
			return fmt.Errorf("address %v: %w", p, err)
		}
	}
	return h.LinkSetUp(link)
}

// Health is a snapshot of a region interface.
type Health struct {
	Up            bool
	Endpoint      string
	LastHandshake time.Time
}

// Inspect reads the interface state from inside the region netns.
func Inspect(region vnetns.NsHandle, name string) (Health, error) {
	var hl Health
	err := netns.InNS(region, func() error {
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err // missing interface: not up
		}
		hl.Up = link.Attrs().Flags&net.FlagUp != 0
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer c.Close()
		d, err := c.Device(name)
		if err != nil {
			return err
		}
		if len(d.Peers) > 0 {
			p := d.Peers[0]
			hl.LastHandshake = p.LastHandshakeTime
			if p.Endpoint != nil {
				hl.Endpoint = p.Endpoint.String()
			}
		}
		return nil
	})
	return hl, err
}

func resolveEndpoint(ctx context.Context, hostport string) (*net.UDPAddr, error) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return net.UDPAddrFromAddrPort(ap), nil
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("endpoint %q: %w", hostport, err)
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve endpoint %q: %v", host, err)
	}
	return net.ResolveUDPAddr("udp4", net.JoinHostPort(ips[0].String(), port))
}

func ipnets(ps []netip.Prefix) []net.IPNet {
	out := make([]net.IPNet, 0, len(ps))
	for _, p := range ps {
		out = append(out, net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
	}
	return out
}
