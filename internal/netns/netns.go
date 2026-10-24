// Package netns builds a region's network namespace (decision 0003):
//
//   - a veth pair for tailscaled's own (underlay) traffic, NATed out of the
//     container's uplink, with the region's UDP port DNATed back in;
//   - policy routing that sends forwarded exit traffic (iif tailscale0) only
//     into the region's WireGuard interface, with unreachable fallbacks so a
//     missing tunnel route means dropped, never the underlay;
//   - resolver routes through the tunnel, also with unreachable fallbacks;
//   - nftables: forward kill switch, DNS kill switch on the veth, and
//     masquerade out of the tunnel.
//
// All configuration goes through netlink and nftables; nothing shells out.
package netns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	InnerVeth  = "veth0"
	TunDev     = "tailscale0"
	exitTable  = 100
	rulePrio   = 100
	fallbackMt = 4096 // metric of the unreachable fallback routes
)

// Layout describes one region's namespace. Index selects the veth subnet
// 10.200.<Index>.0/30.
type Layout struct {
	ID        string
	Index     int
	Port      int
	Resolvers []netip.Addr
}

func (l Layout) NSName() string    { return "rg-" + l.ID }
func (l Layout) WGName() string    { return "wg-" + l.ID }
func (l Layout) OuterVeth() string { return "vo-" + l.ID }

// NSPath is where vishvananda/netns bind-mounts named namespaces (/run/netns,
// which is not always reachable as /var/run/netns, e.g. in distroless images).
func (l Layout) NSPath() string { return filepath.Join("/run/netns", l.NSName()) }

func (l Layout) OuterIP() netip.Addr { return netip.AddrFrom4([4]byte{10, 200, byte(l.Index), 1}) }
func (l Layout) InnerIP() netip.Addr { return netip.AddrFrom4([4]byte{10, 200, byte(l.Index), 2}) }

// Outer is the container's own network namespace (where NordTail runs).
type Outer struct {
	NS     netns.NsHandle
	Uplink string // interface with the default route, e.g. eth0
}

// DetectOuter captures the process's network namespace and its uplink.
func DetectOuter() (*Outer, error) {
	ns, err := netns.GetFromPid(os.Getpid())
	if err != nil {
		return nil, fmt.Errorf("get own netns: %w", err)
	}
	routes, err := netlink.RouteGet(net.IPv4(1, 1, 1, 1))
	if err != nil || len(routes) == 0 {
		return nil, fmt.Errorf("no default route in container netns: %v", err)
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return nil, err
	}
	if err := writeSysctl("net/ipv4/ip_forward", "1"); err != nil {
		return nil, err
	}
	return &Outer{NS: ns, Uplink: link.Attrs().Name}, nil
}

// Create (re)creates the region namespace and its veth pair. Any stale
// namespace or veth with the same names is removed first.
func Create(l Layout) (netns.NsHandle, error) {
	_ = Delete(l)

	ns, err := newNamed(l.NSName())
	if err != nil {
		return netns.None(), fmt.Errorf("create netns %s: %w", l.NSName(), err)
	}
	fail := func(err error) (netns.NsHandle, error) {
		ns.Close()
		_ = Delete(l)
		return netns.None(), err
	}

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: l.OuterVeth()}, PeerName: InnerVeth}
	if err := netlink.LinkAdd(veth); err != nil {
		return fail(fmt.Errorf("add veth: %w", err))
	}
	peer, err := netlink.LinkByName(InnerVeth)
	if err != nil {
		return fail(fmt.Errorf("find veth peer: %w", err))
	}
	if err := netlink.LinkSetNsFd(peer, int(ns)); err != nil {
		return fail(fmt.Errorf("move veth peer: %w", err))
	}
	outer, err := netlink.LinkByName(l.OuterVeth())
	if err != nil {
		return fail(err)
	}
	if err := netlink.AddrAdd(outer, addr(l.OuterIP(), 30)); err != nil {
		return fail(fmt.Errorf("outer veth addr: %w", err))
	}
	if err := netlink.LinkSetUp(outer); err != nil {
		return fail(err)
	}

	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return fail(err)
	}
	defer h.Close()
	lo, err := h.LinkByName("lo")
	if err != nil {
		return fail(err)
	}
	if err := h.LinkSetUp(lo); err != nil {
		return fail(err)
	}
	inner, err := h.LinkByName(InnerVeth)
	if err != nil {
		return fail(err)
	}
	if err := h.AddrAdd(inner, addr(l.InnerIP(), 30)); err != nil {
		return fail(fmt.Errorf("inner veth addr: %w", err))
	}
	if err := h.LinkSetUp(inner); err != nil {
		return fail(err)
	}
	// Underlay: tailscaled's own traffic leaves via the veth.
	if err := h.RouteAdd(&netlink.Route{LinkIndex: inner.Attrs().Index, Gw: l.OuterIP().AsSlice()}); err != nil {
		return fail(fmt.Errorf("underlay default route: %w", err))
	}

	// tailscaled refuses to forward unless both families forward.
	if err := inNS(ns, func() error {
		for k, v := range map[string]string{
			"net/ipv4/ip_forward":              "1",
			"net/ipv6/conf/all/forwarding":     "1",
			"net/ipv4/conf/all/rp_filter":      "2",
			"net/ipv4/conf/default/rp_filter":  "2",
			"net/ipv6/conf/all/disable_ipv6":   "0",
			"net/ipv6/conf/default/forwarding": "1",
		} {
			if err := writeSysctl(k, v); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return fail(fmt.Errorf("sysctls: %w", err))
	}
	return ns, nil
}

// Route installs the tunnel routing once the WireGuard interface is inside
// the namespace and up.
func Route(ns netns.NsHandle, l Layout) error {
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return err
	}
	defer h.Close()
	wg, err := h.LinkByName(l.WGName())
	if err != nil {
		return fmt.Errorf("find %s: %w", l.WGName(), err)
	}
	idx := wg.Attrs().Index
	all4 := netip.MustParsePrefix("0.0.0.0/0")
	all6 := netip.MustParsePrefix("::/0")

	routes := []*netlink.Route{
		{LinkIndex: idx, Dst: ipnet(all4), Table: exitTable, Scope: netlink.SCOPE_LINK},
		{Dst: ipnet(all4), Table: exitTable, Type: unix.RTN_UNREACHABLE, Priority: fallbackMt},
		// No IPv6 through the tunnel yet: reject rather than leak.
		{Dst: ipnet(all6), Table: exitTable, Type: unix.RTN_UNREACHABLE, Priority: fallbackMt},
	}
	for _, r := range l.Resolvers {
		p := netip.PrefixFrom(r, r.BitLen())
		if r.Is4() {
			routes = append(routes, &netlink.Route{LinkIndex: idx, Dst: ipnet(p), Scope: netlink.SCOPE_LINK})
		}
		// The kernel deletes the device route when the link goes down; the
		// fallback keeps resolver traffic off the underlay (spike finding 12).
		routes = append(routes, &netlink.Route{Dst: ipnet(p), Type: unix.RTN_UNREACHABLE, Priority: fallbackMt})
	}
	for _, r := range routes {
		if err := h.RouteReplace(r); err != nil {
			return fmt.Errorf("route %v table %d: %w", r.Dst, r.Table, err)
		}
	}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rule := netlink.NewRule()
		rule.IifName = TunDev
		rule.Table = exitTable
		rule.Priority = rulePrio
		rule.Family = fam
		if err := h.RuleAdd(rule); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("rule iif %s: %w", TunDev, err)
		}
	}
	return nil
}

// Delete removes the region namespace (and with it the WireGuard interface
// and the inner veth; the outer veth end goes with its peer).
func Delete(l Layout) error {
	if link, err := netlink.LinkByName(l.OuterVeth()); err == nil {
		_ = netlink.LinkDel(link)
	}
	err := netns.DeleteNamed(l.NSName())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// newNamed creates a named (iproute2-compatible) netns without leaving any
// Go thread inside it.
func newNamed(name string) (netns.NsHandle, error) {
	type res struct {
		ns  netns.NsHandle
		err error
	}
	c := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := netns.Get()
		if err != nil {
			c <- res{err: err}
			return
		}
		defer orig.Close()
		ns, err := netns.NewNamed(name)
		if rerr := netns.Set(orig); rerr != nil {
			// Thread stays locked and dies with this goroutine.
			c <- res{ns: ns, err: errors.Join(err, rerr)}
			return
		}
		runtime.UnlockOSThread()
		c <- res{ns: ns, err: err}
	}()
	r := <-c
	return r.ns, r.err
}

// inNS runs f on a dedicated OS thread inside target. If the thread can't be
// returned to its original namespace it is discarded, never reused.
func inNS(target netns.NsHandle, f func() error) error {
	c := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := netns.Get()
		if err != nil {
			c <- err
			return
		}
		defer orig.Close()
		if err := netns.Set(target); err != nil {
			c <- err
			return
		}
		ferr := f()
		if err := netns.Set(orig); err != nil {
			c <- errors.Join(ferr, fmt.Errorf("restore netns: %w", err))
			return
		}
		runtime.UnlockOSThread()
		c <- ferr
	}()
	return <-c
}

// InNS is inNS for other packages (WireGuard queries inside the region).
func InNS(target netns.NsHandle, f func() error) error { return inNS(target, f) }

func writeSysctl(key, val string) error {
	return os.WriteFile(filepath.Join("/proc/sys", key), []byte(val), 0o644)
}

func addr(a netip.Addr, bits int) *netlink.Addr {
	return &netlink.Addr{IPNet: &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(bits, a.BitLen())}}
}

func ipnet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
