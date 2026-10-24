// Command echo is the E2E harness's stand-in for "the internet". It answers
// HTTP and DNS and reports which source address each request came from, so a
// test can tell whether traffic went through the fake VPN (source = VPN
// egress), leaked via the NordTail host (source = NordTail container), or
// bypassed the exit node (source = test client).
//
// Every request is also logged as one JSON line on stdout; tests grep those
// lines for a per-check nonce to prove that nothing arrived by another path.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type event struct {
	Time  time.Time `json:"t"`
	Proto string    `json:"proto"`
	Src   string    `json:"src"`
	Path  string    `json:"path,omitempty"`
	QName string    `json:"qname,omitempty"`
	QType string    `json:"qtype,omitempty"`
}

var (
	logMu sync.Mutex
	enc   = json.NewEncoder(os.Stdout)
)

func emit(e event) {
	e.Time = time.Now().UTC()
	logMu.Lock()
	defer logMu.Unlock()
	_ = enc.Encode(e)
}

func main() {
	httpAddr := flag.String("http", ":80", "HTTP listen address")
	dnsAddr := flag.String("dns", ":53", "DNS (UDP) listen address")
	answerV4 := flag.String("answer", "", "IPv4 address returned for every A query (default: the address the query arrived on)")
	flag.Parse()

	go serveDNS(*dnsAddr, *answerV4)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		src := hostOnly(r.RemoteAddr)
		emit(event{Proto: "http", Src: src, Path: r.URL.Path})
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(src + "\n"))
	})
	// Bulk download for throughput checks: /bytes?n=<count>.
	mux.HandleFunc("/bytes", func(w http.ResponseWriter, r *http.Request) {
		emit(event{Proto: "http", Src: hostOnly(r.RemoteAddr), Path: r.URL.Path})
		n := 10 << 20
		if v := r.URL.Query().Get("n"); v != "" {
			if p, err := parseSize(v); err == nil {
				n = p
			}
		}
		buf := make([]byte, 64<<10)
		for n > 0 {
			k := min(n, len(buf))
			if _, err := w.Write(buf[:k]); err != nil {
				return
			}
			n -= k
		}
	})
	srv := &http.Server{Addr: *httpAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func parseSize(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, &net.ParseError{Type: "size", Text: s}
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0, &net.ParseError{Type: "size", Text: s}
		}
	}
	return n, nil
}

func hostOnly(addr string) string {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().Unmap().String()
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// serveDNS answers every query: TXT with the querying source address, A with
// a fixed address (or the local address the query arrived on), AAAA with
// nothing. It is deliberately not a real resolver.
func serveDNS(addr, answerV4 string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("dns listen: %v", err)
	}
	var fixed netip.Addr
	if answerV4 != "" {
		fixed = netip.MustParseAddr(answerV4)
	}
	buf := make([]byte, 1500)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("dns read: %v", err)
			continue
		}
		resp, q, ok := answer(buf[:n], hostOnly(raddr.String()), fixed)
		if q != nil {
			emit(event{Proto: "dns", Src: hostOnly(raddr.String()), QName: strings.TrimSuffix(q.Name.String(), "."), QType: q.Type.String()})
		}
		if ok {
			_, _ = pc.WriteTo(resp, raddr)
		}
	}
}

func answer(req []byte, src string, fixed netip.Addr) ([]byte, *dnsmessage.Question, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil {
		return nil, nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, nil, false
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 0}
	switch q.Type {
	case dnsmessage.TypeTXT:
		_ = b.TXTResource(rh, dnsmessage.TXTResource{TXT: []string{src}})
	case dnsmessage.TypeA:
		a := fixed
		if !a.IsValid() {
			a = netip.MustParseAddr("192.0.2.1")
		}
		if a.Is4() {
			_ = b.AResource(rh, dnsmessage.AResource{A: a.As4()})
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil, &q, false
	}
	return out, &q, true
}
