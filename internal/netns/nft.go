package netns

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	regionTable = "nordtail"
	outerTable  = "nordtail_outer"
)

// Firewall installs the region's nftables table (replacing any previous one):
//
//	forward:     iifname tailscale0 oifname != wg-<id> drop   (kill switch)
//	postrouting: oifname wg-<id> masquerade
//	output:      oifname veth0 udp/tcp dport 53 drop          (DNS kill switch)
//
// tailscaled's own tables in the namespace are left alone.
func Firewall(ns netns.NsHandle, l Layout) error {
	c, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		return err
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: regionTable}
	if err := dropTableIfExists(c, t); err != nil {
		return err
	}
	c.AddTable(t)
	accept := nftables.ChainPolicyAccept

	fwd := c.AddChain(&nftables.Chain{Name: "forward", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept})
	c.AddRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: concat(
		ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, TunDev),
		ifname(expr.MetaKeyOIFNAME, expr.CmpOpNeq, l.WGName()),
		[]expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}},
	)})

	post := c.AddChain(&nftables.Chain{Name: "postrouting", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &accept})
	c.AddRule(&nftables.Rule{Table: t, Chain: post, Exprs: concat(
		ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, l.WGName()),
		[]expr.Any{&expr.Masq{}},
	)})

	out := c.AddChain(&nftables.Chain{Name: "output", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &accept})
	for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		c.AddRule(&nftables.Rule{Table: t, Chain: out, Exprs: concat(
			ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, InnerVeth),
			dport(proto, 53),
			[]expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}},
		)})
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("region nftables: %w", err)
	}
	return nil
}

// OuterNAT installs the container-side NAT for all regions (replacing the
// previous table): masquerade region underlay traffic out of the uplink and
// DNAT each region's UDP port to its namespace.
func OuterNAT(o *Outer, regions []Layout) error {
	c, err := nftables.New(nftables.WithNetNSFd(int(o.NS)))
	if err != nil {
		return err
	}
	t := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: outerTable}
	if err := dropTableIfExists(c, t); err != nil {
		return err
	}
	c.AddTable(t)
	accept := nftables.ChainPolicyAccept
	pre := c.AddChain(&nftables.Chain{Name: "prerouting", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept})
	post := c.AddChain(&nftables.Chain{Name: "postrouting", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &accept})

	for _, l := range regions {
		in := l.InnerIP().As4()
		c.AddRule(&nftables.Rule{Table: t, Chain: pre, Exprs: concat(
			ifname(expr.MetaKeyIIFNAME, expr.CmpOpEq, o.Uplink),
			dport(unix.IPPROTO_UDP, uint16(l.Port)),
			[]expr.Any{
				&expr.Immediate{Register: 1, Data: in[:]},
				&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(uint16(l.Port))},
				&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2},
			},
		)})
	}
	// ip saddr 10.200.0.0/16 oifname <uplink> masquerade
	c.AddRule(&nftables.Rule{Table: t, Chain: post, Exprs: concat(
		[]expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{255, 255, 0, 0}, Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 200, 0, 0}},
		},
		ifname(expr.MetaKeyOIFNAME, expr.CmpOpEq, o.Uplink),
		[]expr.Any{&expr.Masq{}},
	)})
	if err := c.Flush(); err != nil {
		return fmt.Errorf("outer nftables: %w", err)
	}
	return nil
}

func dropTableIfExists(c *nftables.Conn, t *nftables.Table) error {
	tables, err := c.ListTablesOfFamily(t.Family)
	if err != nil {
		return fmt.Errorf("list nftables tables: %w", err)
	}
	for _, x := range tables {
		if x.Name == t.Name {
			c.DelTable(t)
		}
	}
	return nil
}

func ifname(key expr.MetaKey, op expr.CmpOp, name string) []expr.Any {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: op, Register: 1, Data: b},
	}
}

func dport(proto byte, port uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
	}
}

func concat(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
