// Package dnstest is a scriptable DNS server for hermetic tests (#67). Each
// query is answered by a Handler, which decides per name and type whether to
// answer with records, return an error RCODE or NODATA, delay, truncate, or
// drop it. The server counts every query it receives, in total and per name
// and type, so tests can assert exact wire-query counts.
package dnstest

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Query is one question the server received.
type Query struct {
	Name string          // lowercase, without the trailing dot
	Type dnsmessage.Type // dnsmessage.TypeA, TypeAAAA, TypeCNAME, ...
	TCP  bool            // the query arrived over TCP
}

// Reply scripts the answer to a Query. The zero Reply is NOERROR with no
// records, which the server sends as NODATA (an SOA in the authority section).
type Reply struct {
	A     []string // IPv4 answers for A queries
	AAAA  []string // IPv6 answers for AAAA queries
	CNAME string   // alias answered for every qtype; A/AAAA above are then owned by the target

	RCode    dnsmessage.RCode // e.g. RCodeNameError (NXDOMAIN), RCodeServerFailure, RCodeRefused
	Drop     bool             // send nothing; the client times out
	Delay    time.Duration    // wait before answering
	Truncate bool             // over UDP, answer with TC=1 and no records so the client retries over TCP
}

// Common replies.
var (
	NXDomain = Reply{RCode: dnsmessage.RCodeNameError}
	ServFail = Reply{RCode: dnsmessage.RCodeServerFailure}
	Refused  = Reply{RCode: dnsmessage.RCodeRefused}
	Dropped  = Reply{Drop: true}
)

// Handler answers one query. It may be called concurrently unless the server
// is serial.
type Handler func(Query) Reply

// Options configure a server.
type Options struct {
	// Serial answers one UDP query at a time, like a resolver at its rate
	// limit; a Delay then throttles the whole server.
	Serial bool
	// IPv6 listens on [::1] instead of 127.0.0.1.
	IPv6 bool
}

// Server is a running test DNS server.
type Server struct {
	Addr string // host:port, for -dns-server or dns.NewResolver

	total  atomic.Int64
	mu     sync.Mutex
	counts map[countKey]int64
}

type countKey struct {
	name  string
	qtype dnsmessage.Type
}

// Start runs a concurrent IPv4 server answering with h, stopped on cleanup.
func Start(t testing.TB, h Handler) *Server {
	return StartWith(t, Options{}, h)
}

// StartWith runs a server with options, stopped on cleanup. With IPv6 set and
// no IPv6 loopback available, the test is skipped.
func StartWith(t testing.TB, opts Options, h Handler) *Server {
	t.Helper()
	host := "127.0.0.1"
	if opts.IPv6 {
		host = "::1"
	}
	// UDP and TCP must share a port (a truncated UDP answer is retried over
	// TCP at the same address). The OS picks a free TCP port; the matching UDP
	// port can still be taken or, on Windows, inside a reserved range, so try
	// a few port pairs.
	lc := &net.ListenConfig{}
	var ln net.Listener
	var pc net.PacketConn
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		ln, err = lc.Listen(context.Background(), "tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			if opts.IPv6 {
				t.Skipf("no IPv6 loopback: %v", err)
			}
			t.Fatalf("listen tcp: %v", err)
		}
		pc, err = lc.ListenPacket(context.Background(), "udp", ln.Addr().String())
		if err == nil {
			break
		}
		_ = ln.Close()
	}
	if err != nil {
		t.Fatalf("no free UDP+TCP port pair: %v", err)
	}
	s := &Server{Addr: ln.Addr().String(), counts: map[countKey]int64{}}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.serveUDP(pc, opts.Serial, h)
	}()
	go func() {
		defer wg.Done()
		s.serveTCP(ln, h)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = pc.Close()
		wg.Wait()
	})
	return s
}

// Queries returns how many queries the server has received.
func (s *Server) Queries() int64 { return s.total.Load() }

// QueriesFor returns how many queries for name and qtype the server has
// received. name is matched case-insensitively, with or without a trailing dot.
func (s *Server) QueriesFor(name string, qtype dnsmessage.Type) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[countKey{normalize(name), qtype}]
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func (s *Server) serveUDP(pc net.PacketConn, serial bool, h Handler) {
	buf := make([]byte, 65535)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		answer := func() {
			if resp := s.handle(q, false, h); resp != nil {
				_, _ = pc.WriteTo(resp, src)
			}
		}
		if serial {
			answer()
		} else {
			go answer()
		}
	}
}

func (s *Server) serveTCP(ln net.Listener, h Handler) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var size [2]byte
			if _, err := io.ReadFull(c, size[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			resp := s.handle(q, true, h)
			if resp == nil {
				return
			}
			out := binary.BigEndian.AppendUint16(nil, uint16(len(resp))) //nolint:gosec // DNS messages are under 64 KiB
			_, _ = c.Write(append(out, resp...))
		}(conn)
	}
}

// handle parses a query, asks h, and builds the response (nil means drop).
func (s *Server) handle(msg []byte, tcp bool, h Handler) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return nil
	}
	question, err := p.Question()
	if err != nil {
		return nil
	}
	q := Query{Name: normalize(question.Name.String()), Type: question.Type, TCP: tcp}
	s.total.Add(1)
	s.mu.Lock()
	s.counts[countKey{q.Name, q.Type}]++
	s.mu.Unlock()

	r := h(q)
	if r.Delay > 0 {
		time.Sleep(r.Delay)
	}
	if r.Drop {
		return nil
	}
	resp, err := build(hdr, question, q, r)
	if err != nil {
		return nil
	}
	return resp
}

func build(qh dnsmessage.Header, question dnsmessage.Question, q Query, r Reply) ([]byte, error) {
	hdr := dnsmessage.Header{
		ID:                 qh.ID,
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   qh.RecursionDesired,
		RecursionAvailable: true,
		RCode:              r.RCode,
	}
	if r.Truncate && !q.TCP {
		hdr.Truncated = true
	}
	b := dnsmessage.NewBuilder(nil, hdr)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(question); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}

	answered := 0
	if r.RCode == dnsmessage.RCodeSuccess && !hdr.Truncated {
		rh := func(name dnsmessage.Name, t dnsmessage.Type) dnsmessage.ResourceHeader {
			return dnsmessage.ResourceHeader{Name: name, Type: t, Class: dnsmessage.ClassINET, TTL: 60}
		}
		owner := question.Name
		if r.CNAME != "" {
			target, err := dnsmessage.NewName(fqdn(r.CNAME))
			if err != nil {
				return nil, err
			}
			if err := b.CNAMEResource(rh(owner, dnsmessage.TypeCNAME), dnsmessage.CNAMEResource{CNAME: target}); err != nil {
				return nil, err
			}
			answered++
			owner = target
		}
		switch q.Type {
		case dnsmessage.TypeA:
			for _, a := range r.A {
				ip, err := netip.ParseAddr(a)
				if err != nil || !ip.Is4() {
					continue
				}
				if err := b.AResource(rh(owner, dnsmessage.TypeA), dnsmessage.AResource{A: ip.As4()}); err != nil {
					return nil, err
				}
				answered++
			}
		case dnsmessage.TypeAAAA:
			for _, a := range r.AAAA {
				ip, err := netip.ParseAddr(a)
				if err != nil || !ip.Is6() || ip.Is4In6() {
					continue
				}
				if err := b.AAAAResource(rh(owner, dnsmessage.TypeAAAA), dnsmessage.AAAAResource{AAAA: ip.As16()}); err != nil {
					return nil, err
				}
				answered++
			}
		}
	}

	// Negative answers (NXDOMAIN, and NOERROR without records: NODATA) carry
	// the zone's SOA, as real authoritative servers send.
	if answered == 0 && !hdr.Truncated && (r.RCode == dnsmessage.RCodeSuccess || r.RCode == dnsmessage.RCodeNameError) {
		if err := b.StartAuthorities(); err != nil {
			return nil, err
		}
		zone, err := dnsmessage.NewName(fqdn(zoneOf(q.Name)))
		if err != nil {
			return nil, err
		}
		mname, _ := dnsmessage.NewName("ns." + fqdn(zoneOf(q.Name)))
		rname, _ := dnsmessage.NewName("hostmaster." + fqdn(zoneOf(q.Name)))
		soa := dnsmessage.SOAResource{NS: mname, MBox: rname, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, MinTTL: 60}
		if err := b.SOAResource(dnsmessage.ResourceHeader{Name: zone, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 60}, soa); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func fqdn(name string) string {
	return strings.TrimSuffix(name, ".") + "."
}

// zoneOf guesses the zone apex of name: its last two labels.
func zoneOf(name string) string {
	labels := strings.Split(name, ".")
	if len(labels) <= 2 {
		return name
	}
	return strings.Join(labels[len(labels)-2:], ".")
}
