package dns

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func r8(timeout time.Duration) *net.Resolver {
	return NewResolver(timeout, "8.8.8.8:53")
}

func TestResolveDomain(t *testing.T) {
	timeout := time.Second * 2

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "Known existing domain",
			domain:   "google.com",
			expected: true,
		},
		{
			name:     "Known existing subdomain",
			domain:   "www.google.com",
			expected: true,
		},
		{
			name:     "Likely non-existent domain",
			domain:   "this-domain-should-not-exist-123456789.com",
			expected: false,
		},
		{
			name:     "Likely non-existent subdomain of valid domain",
			domain:   "this-subdomain-should-not-exist-123456789.google.com",
			expected: false,
		},
		{
			name:     "Empty domain",
			domain:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveDomain(context.Background(), r8(timeout), tt.domain, timeout, false)

			if got != tt.expected {
				t.Errorf("ResolveDomain(%q) = %v, want %v (may be network-dependent)",
					tt.domain, got, tt.expected)
			}
		})
	}
}

func TestResolveDomainTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	veryShortTimeout := time.Millisecond * 1

	result := ResolveDomain(context.Background(), r8(veryShortTimeout), "google.com", veryShortTimeout, false)

	if result {
		t.Errorf("Expected timeout with 1ms deadline, but resolution succeeded")
	}
}

func TestResolveDomainWithCustomDNS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping custom DNS test in short mode")
	}

	timeout := time.Second * 2

	dnsServers := []string{
		"8.8.8.8:53",
		"1.1.1.1:53",
	}

	testDomain := "google.com"

	for _, server := range dnsServers {
		t.Run(fmt.Sprintf("DNS_Server_%s", server), func(t *testing.T) {
			result := ResolveDomain(context.Background(), NewResolver(timeout, server), testDomain, timeout, false)

			if !result {
				t.Errorf("Expected %s to resolve using DNS server %s, but it failed", testDomain, server)
			}
		})
	}
}

func TestResolveDomainWithRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping retry test in short mode")
	}

	timeout := time.Second * 2

	records, result := ResolveDomainWithRetry(context.Background(), r8(timeout), "google.com", timeout, false, 3, DefaultTypes)
	if result != OutcomeFound {
		t.Errorf("Expected google.com to resolve with retries, but it failed")
	}
	if len(records) == 0 {
		t.Errorf("Expected resolved records for google.com, got none")
	}

	_, result = ResolveDomainWithRetry(context.Background(), r8(timeout), "this-domain-should-not-exist-123456789.com", timeout, false, 2, DefaultTypes)
	if result == OutcomeFound {
		t.Errorf("Expected non-existent domain to fail even with retries")
	}
}

func TestResolveDomainWithRetryContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping context cancellation test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	timeout := time.Second * 2
	start := time.Now()
	_, result := ResolveDomainWithRetry(ctx, r8(timeout), "google.com", timeout, false, 5, DefaultTypes)
	elapsed := time.Since(start)

	if result == OutcomeFound {
		t.Errorf("Expected cancelled context to prevent resolution, but got true")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Expected near-instant return on cancelled context, took %s", elapsed)
	}
}

func TestCheckWildcard(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping wildcard detection test in short mode")
	}

	timeout := time.Second * 3

	isWildcard, _, err := CheckWildcard(context.Background(), r8(timeout), "google.com", timeout)
	if err != nil {
		t.Fatalf("CheckWildcard returned error: %v", err)
	}
	if isWildcard {
		t.Errorf("Expected google.com to NOT be a wildcard domain")
	}
}

func TestCheckWildcardCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := CheckWildcard(ctx, r8(time.Second), "example.com", time.Second)
	if err == nil {
		t.Errorf("Expected error from cancelled context")
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Outcome
	}{
		{name: "nil", err: nil, want: OutcomeFound},
		{
			name: "nxdomain",
			err:  &net.DNSError{Err: "no such host", Name: "missing.example.com", IsNotFound: true},
			want: OutcomeNXDomain,
		},
		{
			name: "timeout",
			err:  &net.DNSError{Err: "i/o timeout", Name: "slow.example.com", IsTimeout: true},
			want: OutcomeTimeout,
		},
		{
			name: "refused",
			err:  &net.DNSError{Err: "server refused", Name: "blocked.example.com"},
			want: OutcomeRefused,
		},
		{
			name: "refused mixed case",
			err:  &net.DNSError{Err: "REFUSED"},
			want: OutcomeRefused,
		},
		{
			name: "other dns error",
			err:  &net.DNSError{Err: "server misbehaving", Name: "x.example.com"},
			want: OutcomeOther,
		},
		{
			name: "generic error",
			err:  fmt.Errorf("dial udp: connection refused"),
			want: OutcomeOther,
		},
		{
			name: "wrapped nxdomain",
			err:  fmt.Errorf("lookup: %w", &net.DNSError{Err: "no such host", IsNotFound: true}),
			want: OutcomeNXDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.err); got != tt.want {
				t.Errorf("Classify() = %v, want %v", got, tt.want)
			}
		})
	}
}

// startNXDomainUDP serves NXDOMAIN for every query on 127.0.0.1:0 and counts
// datagrams received. The test must request a single record type: ResolveTypes
// still issues one lookup per requested type per attempt.
func startNXDomainUDP(t *testing.T) (addr string, queries *atomic.Int64, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	var n atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			nread, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			n.Add(1)
			if nread < 12 {
				continue
			}
			resp := append([]byte(nil), buf[:nread]...)
			resp[2] |= 0x80                   // QR
			resp[3] = (resp[3] & 0xF0) | 0x03 // NXDOMAIN
			_, _ = pc.WriteTo(resp, src)
		}
	}()
	return pc.LocalAddr().String(), &n, func() {
		_ = pc.Close()
		<-done
	}
}

func TestResolveDomainWithRetryNXDomainNoRetry(t *testing.T) {
	addr, queries, stop := startNXDomainUDP(t)
	defer stop()

	_, outcome := ResolveDomainWithRetry(context.Background(), NewResolver(time.Second, addr), "nope.example.com.", time.Second, false, 3, []string{"A"})
	if outcome != OutcomeNXDomain {
		t.Fatalf("outcome = %v, want NXDomain", outcome)
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("queries = %d, want 1 (NXDOMAIN must not be retried)", got)
	}
}

func startFixedAUDP(t *testing.T, ip [4]byte) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			nread, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:nread]
			off, ok := skipDNSName(q, 12)
			resp := append([]byte(nil), q...)
			if !ok || off+2 > len(q) {
				continue
			}
			qtype := uint16(q[off])<<8 | uint16(q[off+1])
			if qtype == 1 { // A
				resp = dnsAResponse(q, ip, false)
			} else if len(resp) >= 12 {
				resp[2] |= 0x80
				resp[3] = (resp[3] & 0xF0) | 0x03
			}
			if resp != nil {
				_, _ = pc.WriteTo(resp, src)
			}
		}
	}()
	return pc.LocalAddr().String(), func() {
		_ = pc.Close()
		<-done
	}
}

func TestCheckWildcardFingerprint(t *testing.T) {
	addr, stop := startFixedAUDP(t, [4]byte{192, 0, 2, 99})
	defer stop()

	is, fp, err := CheckWildcard(context.Background(), NewResolver(time.Second, addr), "example.com", time.Second)
	if err != nil {
		t.Fatalf("CheckWildcard: %v", err)
	}
	if !is {
		t.Fatal("expected wildcard")
	}
	foundIP := false
	for _, r := range fp {
		if r.Type == "A" && r.Value == "192.0.2.99" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("fingerprint %v missing A 192.0.2.99", fp)
	}
}

func skipDNSName(msg []byte, off int) (int, bool) {
	for off < len(msg) {
		l := int(msg[off])
		if l == 0 {
			return off + 1, true
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return 0, false
			}
			return off + 2, true
		}
		off += 1 + l
	}
	return 0, false
}

func dnsAResponse(query []byte, ip [4]byte, truncated bool) []byte {
	if len(query) < 12 {
		return nil
	}
	qend, ok := skipDNSName(query, 12)
	if !ok || qend+4 > len(query) {
		return nil
	}
	qend += 4
	question := query[12:qend]

	flags := uint16(0x8400) // QR + AA
	if truncated {
		flags |= 0x0200 // TC
	}
	if query[2]&0x01 != 0 {
		flags |= 0x0100 // RD
	}

	resp := make([]byte, 0, 64)
	resp = append(resp, query[0], query[1])
	resp = append(resp, byte(flags>>8), byte(flags))
	resp = append(resp, 0, 1) // QDCOUNT
	if truncated {
		resp = append(resp, 0, 0) // ANCOUNT
	} else {
		resp = append(resp, 0, 1)
	}
	resp = append(resp, 0, 0, 0, 0) // NSCOUNT + ARCOUNT
	resp = append(resp, question...)
	if !truncated {
		resp = append(resp,
			0xC0, 0x0C, // name pointer to question
			0, 1, // TYPE A
			0, 1, // CLASS IN
			0, 0, 0, 60, // TTL
			0, 4, // RDLENGTH
			ip[0], ip[1], ip[2], ip[3],
		)
	}
	return resp
}

func writeTCPDNS(conn net.Conn, msg []byte) error {
	var hdr [2]byte
	hdr[0] = byte(len(msg) >> 8)
	hdr[1] = byte(len(msg))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(msg)
	return err
}

func readTCPDNS(conn net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func startTruncatingDNS(t *testing.T, ip [4]byte) (addr string, udpCount, tcpCount *atomic.Int64, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		_ = ln.Close()
		t.Fatalf("ListenPacket udp: %v", err)
	}

	var udpN, tcpN atomic.Int64
	udpDone := make(chan struct{})
	tcpDone := make(chan struct{})

	go func() {
		defer close(udpDone)
		buf := make([]byte, 512)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			udpN.Add(1)
			resp := dnsAResponse(buf[:n], ip, true)
			if resp != nil {
				_, _ = pc.WriteTo(resp, src)
			}
		}
	}()

	go func() {
		defer close(tcpDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			tcpN.Add(1)
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				q, err := readTCPDNS(c)
				if err != nil {
					return
				}
				resp := dnsAResponse(q, ip, false)
				if resp != nil {
					_ = writeTCPDNS(c, resp)
				}
			}(conn)
		}
	}()

	return ln.Addr().String(), &udpN, &tcpN, func() {
		_ = ln.Close()
		_ = pc.Close()
		<-udpDone
		<-tcpDone
	}
}

func TestResolveTypesTCPFallbackOnTruncation(t *testing.T) {
	ip := [4]byte{192, 0, 2, 1}
	addr, udpN, tcpN, stop := startTruncatingDNS(t, ip)
	defer stop()

	r := NewResolver(2*time.Second, addr)
	recs, _, err := ResolveTypes(context.Background(), r, "big.example.com.", 2*time.Second, []string{"A"})
	if err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}
	if len(recs) != 1 || recs[0].Type != "A" || recs[0].Value != "192.0.2.1" {
		t.Fatalf("records = %v, want A 192.0.2.1", recs)
	}
	if udpN.Load() == 0 {
		t.Fatal("expected a truncated UDP query")
	}
	if tcpN.Load() == 0 {
		t.Fatal("expected TCP fallback after TC=1")
	}
}
