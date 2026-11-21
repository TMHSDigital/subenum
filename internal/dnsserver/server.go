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
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strconv"
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
	// Recursive is the query's RD bit: a stub resolver sets it, while a
	// query meant for an authoritative server (a delegation check, an NSEC
	// walk step) leaves it clear (#406).
	Recursive bool
}

// Reply scripts the answer to a Query. The zero Reply is NOERROR with no
// records, which the server sends as NODATA (an SOA in the authority section).
type Reply struct {
	A     []string // IPv4 answers for A queries
	AAAA  []string // IPv6 answers for AAAA queries
	CNAME string   // alias answered for every qtype; the records here are then owned by the target
	// Chain continues the alias past CNAME: each name is the target of the
	// one before, and the records are then owned by the last. A CNAME query
	// gets only the first alias, as a recursive resolver does not chase it.
	Chain []string
	NS    []string // name servers for NS queries
	MX    []string // "<preference> <host>" (or just "<host>", preference 10) for MX queries
	TXT   []string // texts for TXT queries, one record each
	SRV   []string // "<priority> <weight> <port> <target>" for SRV queries

	// Transfer answers an AXFR query for the queried zone: its SOA, an A
	// record (192.0.2.1) for each of these names, and the SOA again (#85).
	// Nil answers AXFR like any unknown type; set RCode to refuse it.
	Transfer []string

	// Denial adds a DNSSEC denial-of-existence record to a negative answer's
	// authority section, after the SOA: "nsec" or "nsec3" (#234).
	Denial string

	// NSEC adds these NSEC records to the authority section of a negative
	// answer, or of a positive one (a wildcard's), as a zone signed with
	// plain NSEC proves which names do not exist (#437).
	NSEC []NSEC

	// Referral answers as a parent zone's server does for a name in a
	// subzone it delegated (#406): NOERROR, not authoritative, no answer,
	// and an NS record per host here in the authority section, owned by
	// ReferralZone ("" is the queried name). It replaces every answer above.
	Referral     []string
	ReferralZone string

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
	// CountNames keeps a count per name and type for QueriesFor. Tests set
	// it (internal/dnstest does); a lab scan leaves it off, since the map
	// would grow with every candidate (#321).
	CountNames bool
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
	counts map[countKey]int64 // nil unless Options.CountNames

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
	lc := &net.ListenConfig{}
	pc, ln, err := bindPair(host, pairListeners{
		packet: func(addr string) (net.PacketConn, error) {
			return lc.ListenPacket(context.Background(), "udp", addr)
		},
		stream: func(addr string) (net.Listener, error) {
			return lc.Listen(context.Background(), "tcp", addr)
		},
	}, randomPort)
	if err != nil {
		if opts.IPv6 && !errors.Is(err, errNoPair) {
			return nil, fmt.Errorf("%w: %w", ErrNoIPv6, err)
		}
		return nil, err
	}
	s := &Server{Addr: ln.Addr().String(), closers: []io.Closer{ln, pc}, conns: map[net.Conn]struct{}{}}
	if opts.CountNames {
		s.counts = map[countKey]int64{}
	}

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

// pairListeners binds one UDP and one TCP listener; tests replace it to
// simulate ports that are taken or reserved.
type pairListeners struct {
	packet func(addr string) (net.PacketConn, error)
	stream func(addr string) (net.Listener, error)
}

// errNoPair means every attempt to bind a UDP+TCP pair on one port failed.
var errNoPair = errors.New("no free UDP+TCP port pair")

// pairAttempts caps bindPair's tries.
const pairAttempts = 32

// randomPort returns a port in 20000-59999 for bindPair's later attempts.
func randomPort() int { return 20000 + mrand.IntN(40000) }

// bindPair binds UDP and TCP on the same loopback port: a truncated UDP
// answer is retried over TCP at the same address. The first attempt lets the
// OS pick the UDP port. Later attempts use random ports from next, because
// the OS hands out ephemeral ports in sequence and, on Windows, retrying with
// port 0 walks through one block of reserved TCP ports instead of leaving it
// (#204). An error binding the OS-picked UDP port is returned as is: the
// host cannot listen at all.
func bindPair(host string, l pairListeners, next func() int) (net.PacketConn, net.Listener, error) {
	var lastErr error
	for attempt := 0; attempt < pairAttempts; attempt++ {
		port := "0"
		if attempt > 0 {
			port = strconv.Itoa(next())
		}
		pc, err := l.packet(net.JoinHostPort(host, port))
		if err != nil {
			if attempt == 0 {
				return nil, nil, fmt.Errorf("listen udp: %w", err)
			}
			lastErr = err
			continue
		}
		ln, err := l.stream(pc.LocalAddr().String())
		if err == nil {
			return pc, ln, nil
		}
		_ = pc.Close()
		lastErr = err
	}
	return nil, nil, fmt.Errorf("%w: %w", errNoPair, lastErr)
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
// It panics unless the server was started with Options.CountNames.
func (s *Server) QueriesFor(name string, qtype dnsmessage.Type) int64 {
	if s.counts == nil {
		panic("dnsserver: QueriesFor needs Options.CountNames")
	}
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
			// Returning would let net/http send an implicit 200 if the server
			// sees cancellation first. Abort without writing any response.
			panic(http.ErrAbortHandler)
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
	q := Query{Name: normalize(question.Name.String()), Type: question.Type, TCP: tcp, Recursive: hdr.RecursionDesired}
	s.total.Add(1)
	if s.counts != nil {
		s.mu.Lock()
		s.counts[countKey{q.Name, q.Type}]++
		s.mu.Unlock()
	}

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
	if !tcp && len(resp) > udpPayload(&p) {
		// As a real server does: an answer too big for the client's UDP
		// buffer goes out truncated, so the client asks again over TCP.
		r.Truncate = true
		if resp, err = build(hdr, question, q, r); err != nil {
			return nil
		}
	}
	return resp
}

// udpPayload returns the UDP answer size the query advertises in its EDNS
// OPT record, or 512 (RFC 1035) without one. p is past the question.
func udpPayload(p *dnsmessage.Parser) int {
	const plain = 512
	if p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return plain
	}
	extra, err := p.AllAdditionals()
	if err != nil {
		return plain
	}
	for _, rr := range extra {
		if rr.Header.Type == dnsmessage.TypeOPT {
			return max(plain, int(rr.Header.Class))
		}
	}
	return plain
}

func build(qh dnsmessage.Header, question dnsmessage.Question, q Query, r Reply) ([]byte, error) {
	referral := len(r.Referral) > 0 && r.RCode == dnsmessage.RCodeSuccess
	hdr := dnsmessage.Header{
		ID:                 qh.ID,
		Response:           true,
		Authoritative:      !referral, // a referral is not an answer from the zone itself
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

	if referral && !hdr.Truncated {
		if err := addReferral(&b, q.Name, r); err != nil {
			return nil, err
		}
		return b.Finish()
	}

	answered := 0
	if r.RCode == dnsmessage.RCodeSuccess && !hdr.Truncated && !referral {
		n, err := addAnswers(&b, question.Name, q.Type, r)
		if err != nil {
			return nil, err
		}
		answered = n
	}

	// Negative answers (NXDOMAIN, and NOERROR without records: NODATA) carry
	// the zone's SOA, as real authoritative servers send.
	if answered == 0 && !hdr.Truncated && (r.RCode == dnsmessage.RCodeSuccess || r.RCode == dnsmessage.RCodeNameError) {
		if err := addSOA(&b, q.Name); err != nil {
			return nil, err
		}
		if err := addDenial(&b, q.Name, r.Denial); err != nil {
			return nil, err
		}
		if err := addNSEC(&b, r.NSEC); err != nil {
			return nil, err
		}
	} else if len(r.NSEC) > 0 && answered > 0 {
		// A wildcard answer proves with NSEC that the name itself does not
		// exist, as a signed zone's server does.
		if err := b.StartAuthorities(); err != nil {
			return nil, err
		}
		if err := addNSEC(&b, r.NSEC); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// addReferral adds r's referral to the authority section: one NS record per
// host, owned by r.ReferralZone, or by name when that is empty (#406).
func addReferral(b *dnsmessage.Builder, name string, r Reply) error {
	if err := b.StartAuthorities(); err != nil {
		return err
	}
	zone := r.ReferralZone
	if zone == "" {
		zone = name
	}
	owner, err := dnsmessage.NewName(fqdn(zone))
	if err != nil {
		return err
	}
	for _, h := range r.Referral {
		host, err := dnsmessage.NewName(fqdn(h))
		if err != nil {
			continue
		}
		if err := b.NSResource(rrHeader(owner, dnsmessage.TypeNS), dnsmessage.NSResource{NS: host}); err != nil {
			return err
		}
	}
	return nil
}

// NSEC is one NSEC record (#437): Owner is followed by Next in the zone's
// canonical order, so no name between them exists. Names are lowercase,
// without the trailing dot; the type bitmap lists A, RRSIG and NSEC.
type NSEC struct {
	Owner, Next string
}

// addNSEC adds records to the authority section the caller started. Next
// is written uncompressed, as RFC 4034 requires.
func addNSEC(b *dnsmessage.Builder, records []NSEC) error {
	for _, rec := range records {
		owner, err := dnsmessage.NewName(fqdn(rec.Owner))
		if err != nil {
			return err
		}
		var data []byte
		if next := strings.TrimSuffix(rec.Next, "."); next != "" {
			for label := range strings.SplitSeq(next, ".") {
				if label == "" || len(label) > 63 {
					return fmt.Errorf("dnsserver: bad NSEC next name %q", rec.Next)
				}
				data = append(append(data, byte(len(label))), label...) //nolint:gosec // checked above: at most 63
			}
		}
		data = append(data, 0)
		// Window 0, 6 bytes: A (1), RRSIG (46) and NSEC (47).
		data = append(data, 0, 6, 0x40, 0, 0, 0, 0, 0x02|0x01)
		t := dnsmessage.Type(47)
		if err := b.UnknownResource(dnsmessage.ResourceHeader{Name: owner, Type: t, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.UnknownResource{Type: t, Data: data}); err != nil {
			return err
		}
	}
	return nil
}

// addDenial adds an NSEC or NSEC3 record for name's zone to the authority
// section addSOA started. Only the record type matters to clients here, so
// the data is minimal but well formed: NSEC names the root as next and
// covers A; NSEC3 is SHA-1, no salt, a zero hash, and covers A.
func addDenial(b *dnsmessage.Builder, name, denial string) error {
	bitmapA := []byte{0, 1, 0x40} // window 0, one byte, type A
	var t dnsmessage.Type
	var data []byte
	switch denial {
	case "":
		return nil
	case "nsec":
		t, data = 47, append([]byte{0}, bitmapA...)
	case "nsec3":
		t = 50
		data = append([]byte{1, 0, 0, 0, 0, 20}, make([]byte, 20)...)
		data = append(data, bitmapA...)
	default:
		return fmt.Errorf("dnsserver: unknown Denial %q", denial)
	}
	owner, err := dnsmessage.NewName(fqdn(zoneOf(name)))
	if err != nil {
		return err
	}
	return b.UnknownResource(dnsmessage.ResourceHeader{Name: owner, Type: t, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.UnknownResource{Type: t, Data: data})
}

// answerBuilder adds r's records of one query type, owned by owner, and
// returns how many it added. Values that are not valid for the type are
// skipped.
type answerBuilder func(b *dnsmessage.Builder, owner dnsmessage.Name, r Reply) (int, error)

// answerBuilders holds one builder per query type the server answers; a new
// record type is one entry here. Other types get only the CNAME, if any.
var answerBuilders = map[dnsmessage.Type]answerBuilder{
	dnsmessage.TypeA:    addA,
	dnsmessage.TypeAAAA: addAAAA,
	dnsmessage.TypeNS:   addNS,
	dnsmessage.TypeMX:   addMX,
	dnsmessage.TypeTXT:  addTXT,
	dnsmessage.TypeSRV:  addSRV,
	dnsmessage.TypeAXFR: addTransfer,
}

// addSRV adds one SRV record per "<priority> <weight> <port> <target>"
// value; malformed values are skipped.
func addSRV(b *dnsmessage.Builder, owner dnsmessage.Name, r Reply) (int, error) {
	n := 0
	for _, v := range r.SRV {
		f := strings.Fields(v)
		if len(f) != 4 {
			continue
		}
		var nums [3]uint16
		ok := true
		for i := range nums {
			x, err := strconv.ParseUint(f[i], 10, 16)
			ok = ok && err == nil
			nums[i] = uint16(x)
		}
		target, err := dnsmessage.NewName(fqdn(f[3]))
		if !ok || err != nil {
			continue
		}
		if err := b.SRVResource(rrHeader(owner, dnsmessage.TypeSRV), dnsmessage.SRVResource{Priority: nums[0], Weight: nums[1], Port: nums[2], Target: target}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// addTransfer answers a zone transfer in one message: the zone's SOA, an A
// record per name in r.Transfer, and the SOA again. Nil Transfer adds nothing.
func addTransfer(b *dnsmessage.Builder, owner dnsmessage.Name, r Reply) (int, error) {
	if r.Transfer == nil {
		return 0, nil
	}
	soa := func() error {
		mname, _ := dnsmessage.NewName("ns." + owner.String())
		rname, _ := dnsmessage.NewName("hostmaster." + owner.String())
		return b.SOAResource(rrHeader(owner, dnsmessage.TypeSOA),
			dnsmessage.SOAResource{NS: mname, MBox: rname, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, MinTTL: 60})
	}
	if err := soa(); err != nil {
		return 0, err
	}
	n := 1
	for _, name := range r.Transfer {
		host, err := dnsmessage.NewName(fqdn(name))
		if err != nil {
			continue
		}
		if err := b.AResource(rrHeader(host, dnsmessage.TypeA), dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}); err != nil {
			return n, err
		}
		n++
	}
	return n + 1, soa()
}

// rrHeader is the header every answer record carries.
func rrHeader(name dnsmessage.Name, t dnsmessage.Type) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: name, Type: t, Class: dnsmessage.ClassINET, TTL: 60}
}

// addAnswers adds r's CNAME, if any, then the records of type qtype, owned by
// the CNAME target when there is one. It returns how many records it added.
func addAnswers(b *dnsmessage.Builder, owner dnsmessage.Name, qtype dnsmessage.Type, r Reply) (int, error) {
	answered := 0
	if r.CNAME != "" {
		aliases := []string{r.CNAME}
		if qtype != dnsmessage.TypeCNAME {
			aliases = append(aliases, r.Chain...)
		}
		for _, alias := range aliases {
			target, err := dnsmessage.NewName(fqdn(alias))
			if err != nil {
				return answered, err
			}
			if err := b.CNAMEResource(rrHeader(owner, dnsmessage.TypeCNAME), dnsmessage.CNAMEResource{CNAME: target}); err != nil {
				return answered, err
			}
			answered++
			owner = target
		}
	}
	add, ok := answerBuilders[qtype]
	if !ok {
		return answered, nil
	}
	n, err := add(b, owner, r)
	return answered + n, err
}

// addAddrs adds one record per value that parses as an address keep accepts.
func addAddrs(values []string, keep func(netip.Addr) bool, add func(netip.Addr) error) (int, error) {
	n := 0
	for _, v := range values {
		ip, err := netip.ParseAddr(v)
		if err != nil || !keep(ip) {
			continue
		}
		if err := add(ip); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func addA(b *dnsmessage.Builder, owner dnsmessage.Name, r Reply) (int, error) {
	return addAddrs(r.A, netip.Addr.Is4, func(ip netip.Addr) error {
		return b.AResource(rrHeader(owner, dnsmessage.TypeA), dnsmessage.AResource{A: ip.As4()})
	})
}

func addAAAA(b *dnsmessage.Builder, owner dnsmessage.Name, r Reply) (int, error) {
	isV6 := func(ip netip.Addr) bool { return ip.Is6() && !ip.Is4In6() }
	return addAddrs(r.AAAA, isV6, func(ip netip.Addr) error {
		return b.AAAAResource(rrHeader(owner, dnsmessage.TypeAAAA), dnsmessage.AAAAResource{AAAA: ip.As16()})
	})
}

// addNS adds one NS record per host that is a valid name.
func addNS(b *dnsmessage.Builder, owner dnsmessage.Name, r Reply) (int, error) {
	n := 0
	for _, h := range r.NS {
		host, err := dnsmessage.NewName(fqdn(h))
		if err != nil {
			continue
		}
		if err := b.NSResource(rrHeader(owner, dnsmessage.TypeNS), dnsmessage.NSResource{NS: host}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// addMX adds one MX record per "<preference> <host>" or "<host>" value.
func addMX(b *dnsmessage.Builder, owner dnsmessage.Name, r Reply) (int, error) {
	n := 0
	for _, v := range r.MX {
		pref, hostStr := uint16(10), v
		if p, h, ok := strings.Cut(v, " "); ok {
			pv, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				continue
			}
			pref, hostStr = uint16(pv), strings.TrimSpace(h)
		}
		host, err := dnsmessage.NewName(fqdn(hostStr))
		if err != nil {
			continue
		}
		if err := b.MXResource(rrHeader(owner, dnsmessage.TypeMX), dnsmessage.MXResource{Pref: pref, MX: host}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// addTXT adds one TXT record per text, split into 255-byte strings.
func addTXT(b *dnsmessage.Builder, owner dnsmessage.Name, r Reply) (int, error) {
	n := 0
	for _, v := range r.TXT {
		var parts []string
		for len(v) > 255 {
			parts, v = append(parts, v[:255]), v[255:]
		}
		parts = append(parts, v)
		if err := b.TXTResource(rrHeader(owner, dnsmessage.TypeTXT), dnsmessage.TXTResource{TXT: parts}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// addSOA adds the authority section holding the SOA of name's zone.
func addSOA(b *dnsmessage.Builder, name string) error {
	if err := b.StartAuthorities(); err != nil {
		return err
	}
	zone, err := dnsmessage.NewName(fqdn(zoneOf(name)))
	if err != nil {
		return err
	}
	mname, _ := dnsmessage.NewName("ns." + fqdn(zoneOf(name)))
	rname, _ := dnsmessage.NewName("hostmaster." + fqdn(zoneOf(name)))
	soa := dnsmessage.SOAResource{NS: mname, MBox: rname, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, MinTTL: 60}
	return b.SOAResource(dnsmessage.ResourceHeader{Name: zone, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 60}, soa)
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
