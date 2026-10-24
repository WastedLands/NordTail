package wg

import (
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"time"

	vnetns "github.com/vishvananda/netns"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/WastedLands/NordTail/internal/netns"
)

// Probe proves the tunnel works end to end: it sends one DNS query from
// inside the region netns to the region's resolver (routed only through the
// tunnel) and waits for any well-formed answer, NXDOMAIN included.
func Probe(region vnetns.NsHandle, resolver netip.Addr, timeout time.Duration) error {
	var conn net.Conn
	// The socket is created inside the region netns and keeps it afterwards.
	if err := netns.InNS(region, func() error {
		var err error
		conn, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(resolver, 53)))
		return err
	}); err != nil {
		return err
	}
	defer conn.Close()

	var id [2]byte
	_, _ = rand.Read(id[:])
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: uint16(id[0])<<8 | uint16(id[1]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("health.nordtail.invalid."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	q, err := msg.Pack()
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err == nil && h.Response && h.ID == msg.Header.ID {
			return nil
		}
		if err != nil {
			return errors.New("malformed DNS answer")
		}
	}
}
