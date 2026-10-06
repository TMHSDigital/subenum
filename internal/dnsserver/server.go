// Package dnsserver is a scriptable local DNS server (#67). Each query is
// answered by a Handler, which decides per name and type whether to answer
// with records, return an error RCODE or NODATA, delay, truncate, or drop it.
// The server counts every query it receives, in total and per name and type.
//
// It backs the hermetic tests (through internal/dnstest) and -simulate-zone
// labs (#76), which point the real resolver at a loopback server.
package dnsserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
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

// Server is a running DNS server.
type Server struct {
	Addr string // host:port, for -dns-server or dns.NewResolver

	TLSAddr string         // DoT listener after ListenTLS, for tls://<TLSAddr>
	RootCAs *x509.CertPool // trusts the ListenTLS certificate

	connections   atomic.Int64
	streamQueries atomic.Int64
	closeAfter    atomic.Int64 // close stream connections after this many answers (0 = never)

	total  atomic.Int64
	mu     sync.Mutex
	counts map[countKey]int64

	closers []io.Closer
	// wg covers every goroutine the server starts: listeners, stream
	// connections and UDP answers, so Close returns only once no handler
	// can still run (#122).
	wg      sync.WaitGroup
	connMu  sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool
}

type countKey struct {
	name  string
	qtype dnsmessage.Type
}

// ErrNoIPv6 is returned by Listen when IPv6 is requested and the host has no
// IPv6 loopback.
var ErrNoIPv6 = errors.New("no IPv6 loopback")

// Listen runs a server on a free loopback port answering with h, until Close.
func Listen(opts Options, h Handler) (*Server, error) {
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
	// UDP is bound first: Windows reserves blocks of UDP ports, and binding
	// UDP on a port the OS picked for TCP kept landing inside one.
	for attempt := 0; attempt < 20; attempt++ {
		pc, err = lc.ListenPacket(context.Background(), "udp", net.JoinHostPort(host, "0"))
		if err != nil {
			if opts.IPv6 {
				return nil, fmt.Errorf("%w: %w", ErrNoIPv6, err)
			}
			return nil, fmt.Errorf("listen udp: %w", err)
		}
		ln, err = lc.Listen(context.Background(), "tcp", pc.LocalAddr().String())
		if err == nil {
			break
		}
		_ = pc.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("no free UDP+TCP port pair: %w", err)
	}
	s := &Server{Addr: ln.Addr().String(), counts: map[countKey]int64{}, closers: []io.Closer{ln, pc}, conns: map[net.Conn]struct{}{}}

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.serveUDP(pc, opts.Serial, h)
	}()
	go func() {
		defer s.wg.Done()
		s.serveTCP(ln, h)
	}()
	return s, nil
}

// Close stops the server: it closes the listeners and every open stream
// connection, and waits until no handler is running, including delayed UDP
// answers and connections parked on a dropped query.
func (s *Server) Close() {
	s.connMu.Lock()
	s.closing = true
	for c := range s.conns {
		_ = c.Close()
	}
	s.connMu.Unlock()
	for _, c := range s.closers {
		_ = c.Close()
	}
	s.wg.Wait()
}

// CloseStreamsAfter makes the server close each TCP or TLS connection after
// answering n queries on it, as servers with a short idle timeout or a
// per-connection query limit do. 0 restores the default (never).
func (s *Server) CloseStreamsAfter(n int) { s.closeAfter.Store(int64(n)) }

// track registers an open stream connection; it reports false once the
// server is closing, and the caller must then close c itself.
func (s *Server) track(c net.Conn) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.closing {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.connMu.Lock()
	delete(s.conns, c)
	s.connMu.Unlock()
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
			s.wg.Go(answer)
		}
	}
}

// serveTCP answers length-prefixed queries on each connection until the
// client closes it, so DoT clients can reuse a connection.
func (s *Server) serveTCP(ln net.Listener, h Handler) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if !s.track(conn) {
			_ = conn.Close()
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer s.untrack(c)
			defer func() { _ = c.Close() }()
			for answered := int64(1); ; answered++ {
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
					// A dropped query: keep the connection open without
					// answering, as an unresponsive server would, until the
					// client gives up. Closing it would read as an error.
					_, _ = io.Copy(io.Discard, c)
					return
				}
				out := binary.BigEndian.AppendUint16(nil, uint16(len(resp))) //nolint:gosec // DNS messages are under 64 KiB
				if _, err := c.Write(append(out, resp...)); err != nil {
					return
				}
				s.streamQueries.Add(1)
				if n := s.closeAfter.Load(); n > 0 && answered >= n {
					return
				}
			}
		}(conn)
		s.connections.Add(1)
	}
}

// ListenTLS adds a DNS-over-TLS listener (RFC 7858) answering with h, using a
// freshly generated certificate for 127.0.0.1. Use TLSAddr as tls://<TLSAddr>
// and RootCAs to trust it. Close stops it too.
func (s *Server) ListenTLS(h Handler) error {
	cert, pool, err := selfSignedCert()
	if err != nil {
		return err
	}
	lc := &net.ListenConfig{}
	tcp, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen tls: %w", err)
	}
	ln := tls.NewListener(tcp, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	s.TLSAddr, s.RootCAs = ln.Addr().String(), pool
	s.closers = append(s.closers, ln)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.serveTCP(ln, h)
	}()
	return nil
}

// DoHHandler serves DNS over HTTPS (RFC 8484, POST) answering with h. Run it
// with httptest.NewUnstartedServer(...).StartTLS().
func (s *Server) DoHHandler(h Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "want POST application/dns-message", http.StatusBadRequest)
			return
		}
		q, err := io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := s.handle(q, true, h)
		if resp == nil {
			// A dropped query: hold the request until the client gives up.
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	})
}

// Connections returns how many TCP or TLS connections clients opened.
func (s *Server) Connections() int64 { return s.connections.Load() }

// selfSignedCert makes a short-lived certificate for 127.0.0.1 and ::1.
func selfSignedCert() (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dnstest"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool, nil
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
