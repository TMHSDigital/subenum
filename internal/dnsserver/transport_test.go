package dnsserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// answer is the part of a response the tests check.
type answer struct {
	hdr     dnsmessage.Header
	a       []string // A record values
	records []string // every answer record, as "owner TYPE value"
	soa     string   // owner of the authority SOA, if any
}

func parseAnswer(t *testing.T, msg []byte) answer {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	got := answer{hdr: hdr}
	rrs, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	for _, rr := range rrs {
		var v string
		switch b := rr.Body.(type) {
		case *dnsmessage.AResource:
			v = netip.AddrFrom4(b.A).String()
			got.a = append(got.a, v)
		case *dnsmessage.AAAAResource:
			v = netip.AddrFrom16(b.AAAA).String()
		case *dnsmessage.CNAMEResource:
			v = b.CNAME.String()
		}
		got.records = append(got.records, rr.Header.Name.String()+" "+rr.Header.Type.String()+" "+v)
	}
	auth, err := p.AllAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	for _, rr := range auth {
		if rr.Header.Type == dnsmessage.TypeSOA {
			got.soa = rr.Header.Name.String()
		}
	}
	return got
}

// streamExchange sends one length-prefixed query on c and reads the answer.
func streamExchange(t *testing.T, c net.Conn, msg []byte) []byte {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(msg)))); err != nil { //nolint:gosec // test queries are tiny
		t.Fatal(err)
	}
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		t.Fatalf("read length: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("read answer: %v", err)
	}
	return resp
}

func udpExchange(t *testing.T, addr string, msg []byte) []byte {
	t.Helper()
	var d net.Dialer
	c, err := d.DialContext(context.Background(), "udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("udp answer: %v", err)
	}
	return buf[:n]
}

func tcpExchange(t *testing.T, addr string, msg []byte) []byte {
	t.Helper()
	var d net.Dialer
	c, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return streamExchange(t, c, msg)
}

func dialDoT(t *testing.T, srv *Server) *tls.Conn {
	t.Helper()
	d := tls.Dialer{Config: &tls.Config{RootCAs: srv.RootCAs, MinVersion: tls.VersionTLS12}}
	c, err := d.DialContext(context.Background(), "tcp", srv.TLSAddr)
	if err != nil {
		t.Fatalf("dial DoT: %v", err)
	}
	return c.(*tls.Conn)
}

func postDoH(t *testing.T, client *http.Client, url string, msg []byte) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DoH POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DoH POST status %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Errorf("DoH Content-Type %q, want application/dns-message", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestListenTLSReusesConnection: two DoT queries on one connection are both
// answered and count as one connection, the listener's certificate is trusted
// only through RootCAs, and Close returns promptly once the client is gone.
func TestListenTLSReusesConnection(t *testing.T) {
	var sawStream atomic.Bool
	srv, err := Listen(Options{}, func(Query) Reply { return Reply{A: []string{"192.0.2.9"}} })
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			srv.Close()
		}
	}()
	if err := srv.ListenTLS(func(q Query) Reply {
		if q.TCP {
			sawStream.Store(true)
		}
		return Reply{A: []string{"192.0.2.1"}}
	}); err != nil {
		t.Fatal(err)
	}
	if srv.TLSAddr == "" || srv.RootCAs == nil {
		t.Fatalf("ListenTLS left TLSAddr=%q RootCAs=%v", srv.TLSAddr, srv.RootCAs)
	}

	// Without RootCAs the self-signed certificate must not verify.
	untrusted := tls.Dialer{Config: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}
	if c, err := untrusted.DialContext(context.Background(), "tcp", srv.TLSAddr); err == nil {
		_ = c.Close()
		t.Error("DoT handshake succeeded without trusting RootCAs")
	}
	// That rejected handshake still opened a connection; count from here.
	waitFor(t, func() bool { return srv.Connections() == 1 })
	base := srv.Connections()

	c := dialDoT(t, srv)
	for i, name := range []string{"one.example.com.", "two.example.com."} {
		got := parseAnswer(t, streamExchange(t, c, query(t, name)))
		if !slices.Equal(got.a, []string{"192.0.2.1"}) {
			t.Errorf("query %d: A = %v, want [192.0.2.1] from the DoT handler", i, got.a)
		}
	}
	if !sawStream.Load() {
		t.Error("DoT handler saw Query.TCP = false")
	}
	if got := srv.Connections() - base; got != 1 {
		t.Errorf("Connections() grew by %d for two queries on one DoT connection; want 1", got)
	}
	if got := srv.QueriesFor("one.example.com", dnsmessage.TypeA) + srv.QueriesFor("two.example.com", dnsmessage.TypeA); got != 2 {
		t.Errorf("QueriesFor counted %d DoT queries, want 2", got)
	}

	_ = c.Close()
	start := time.Now()
	srv.Close()
	closed = true
	// Below serveTCP's 5s read deadline, so a connection Close failed to
	// release would show here.
	if took := time.Since(start); took > 4*time.Second {
		t.Errorf("Close took %s after the DoT client left", took)
	}
}

// TestDoHHandler: a POST of application/dns-message is answered; other
// methods and content types are rejected; a dropped query holds the request
// until the client gives up.
func TestDoHHandler(t *testing.T) {
	srv, err := Listen(Options{}, func(Query) Reply { return Reply{} })
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewUnstartedServer(srv.DoHHandler(func(q Query) Reply {
		if q.Name == "dropped.example.com" {
			return Dropped
		}
		if !q.TCP {
			return ServFail
		}
		return Reply{A: []string{"192.0.2.7"}}
	}))
	ts.StartTLS()
	defer ts.Close()
	client := ts.Client()

	got := parseAnswer(t, postDoH(t, client, ts.URL, query(t, "www.example.com.")))
	if got.hdr.RCode != dnsmessage.RCodeSuccess || !slices.Equal(got.a, []string{"192.0.2.7"}) {
		t.Errorf("DoH answer rcode=%v A=%v, want NOERROR [192.0.2.7]", got.hdr.RCode, got.a)
	}
	if got.hdr.ID != 1 {
		t.Errorf("DoH answer ID %d, want the query's 1", got.hdr.ID)
	}

	for _, tc := range []struct {
		name, method, contentType string
	}{
		{"GET", http.MethodGet, ""},
		{"POST wrong content type", http.MethodPost, "text/plain"},
		{"POST no content type", http.MethodPost, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), tc.method, ts.URL, bytes.NewReader(query(t, "www.example.com.")))
			if err != nil {
				t.Fatal(err)
			}
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status %d, want 400", resp.StatusCode)
			}
		})
	}

	t.Run("dropped", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, bytes.NewReader(query(t, "dropped.example.com.")))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/dns-message")
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("dropped DoH query answered with status %d; want the request held until the client gives up", resp.StatusCode)
		}
	})

	// Only the well-formed POSTs reached the handler.
	if got := srv.Queries(); got != 2 {
		t.Errorf("Queries() = %d, want 2 (answered + dropped POST)", got)
	}
}

// TestQueriesForCountsEveryTransport: the same name asked over UDP, TCP, DoT
// and DoH lands in one QueriesFor count, matched case-insensitively and with
// or without the trailing dot.
func TestQueriesForCountsEveryTransport(t *testing.T) {
	h := func(Query) Reply { return Reply{A: []string{"192.0.2.1"}} }
	srv, err := Listen(Options{}, h)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if err := srv.ListenTLS(h); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv.DoHHandler(h))
	ts.StartTLS()
	defer ts.Close()

	msg := query(t, "Mixed.Example.com.")
	exchanges := map[string]func() []byte{
		"UDP": func() []byte { return udpExchange(t, srv.Addr, msg) },
		"TCP": func() []byte { return tcpExchange(t, srv.Addr, msg) },
		"DoT": func() []byte {
			c := dialDoT(t, srv)
			defer func() { _ = c.Close() }()
			return streamExchange(t, c, msg)
		},
		"DoH": func() []byte { return postDoH(t, ts.Client(), ts.URL, msg) },
	}
	for _, name := range []string{"UDP", "TCP", "DoT", "DoH"} {
		if got := parseAnswer(t, exchanges[name]()); !slices.Equal(got.a, []string{"192.0.2.1"}) {
			t.Errorf("%s: A = %v, want [192.0.2.1]", name, got.a)
		}
	}

	for _, name := range []string{"mixed.example.com", "MIXED.example.com.", "mixed.example.com."} {
		if got := srv.QueriesFor(name, dnsmessage.TypeA); got != 4 {
			t.Errorf("QueriesFor(%q, A) = %d, want 4", name, got)
		}
	}
	if got := srv.QueriesFor("mixed.example.com", dnsmessage.TypeAAAA); got != 0 {
		t.Errorf("QueriesFor(AAAA) = %d, want 0", got)
	}
	if got := srv.Queries(); got != 4 {
		t.Errorf("Queries() = %d, want 4", got)
	}
}

// TestTruncateRetriesOverTCP: a Truncate reply sets TC with no records over
// UDP, and the TCP retry at the same address gets the full answer.
func TestTruncateRetriesOverTCP(t *testing.T) {
	want := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	srv, err := Listen(Options{}, func(Query) Reply { return Reply{A: want, Truncate: true} })
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	msg := query(t, "big.example.com.")

	udp := parseAnswer(t, udpExchange(t, srv.Addr, msg))
	if !udp.hdr.Truncated || len(udp.a) != 0 {
		t.Errorf("UDP: TC=%v A=%v, want TC=1 and no records", udp.hdr.Truncated, udp.a)
	}
	tcp := parseAnswer(t, tcpExchange(t, srv.Addr, msg))
	if tcp.hdr.Truncated || !slices.Equal(tcp.a, want) {
		t.Errorf("TCP: TC=%v A=%v, want TC=0 and %v", tcp.hdr.Truncated, tcp.a, want)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func queryType(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// TestReplies: build turns each kind of Reply into the response a real
// server would send: records of the asked type only, CNAME chains, error
// RCODEs, and an SOA on negative answers.
func TestReplies(t *testing.T) {
	replies := map[string]Reply{
		"a.example.com":       {A: []string{"192.0.2.1", "nope", "2001:db8::1"}, AAAA: []string{"2001:db8::1"}},
		"aaaa.example.com":    {AAAA: []string{"2001:db8::1", "192.0.2.1", "::ffff:192.0.2.1"}, A: []string{"192.0.2.1"}},
		"alias.example.com":   {CNAME: "target.example.net", A: []string{"192.0.2.5"}, AAAA: []string{"2001:db8::5", "bad"}},
		"bare.example.com":    {CNAME: "target.example.net."},
		"nxalias.example.com": {RCode: dnsmessage.RCodeNameError, CNAME: "target.example.net", A: []string{"192.0.2.5"}},
		"nx.sub.example.com":  NXDomain,
		"empty.example.com":   {},
		"example.com":         {},
		"fail.example.com":    ServFail,
		"refused.example.com": Refused,
	}
	srv, err := Listen(Options{}, func(q Query) Reply { return replies[q.Name] })
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	for _, tc := range []struct {
		name    string
		qtype   dnsmessage.Type
		rcode   dnsmessage.RCode
		records []string
		soa     string
	}{
		{"a.example.com.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []string{"a.example.com. TypeA 192.0.2.1"}, ""},
		{"aaaa.example.com.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, []string{"aaaa.example.com. TypeAAAA 2001:db8::1"}, ""},
		{"alias.example.com.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []string{"alias.example.com. TypeCNAME target.example.net.", "target.example.net. TypeA 192.0.2.5"}, ""},
		{"alias.example.com.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, []string{"alias.example.com. TypeCNAME target.example.net.", "target.example.net. TypeAAAA 2001:db8::5"}, ""},
		{"alias.example.com.", dnsmessage.TypeTXT, dnsmessage.RCodeSuccess, []string{"alias.example.com. TypeCNAME target.example.net."}, ""},
		{"bare.example.com.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []string{"bare.example.com. TypeCNAME target.example.net."}, ""},
		{"nxalias.example.com.", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil, "example.com."},
		{"a.example.com.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, []string{"a.example.com. TypeAAAA 2001:db8::1"}, ""},
		{"a.example.com.", dnsmessage.TypeTXT, dnsmessage.RCodeSuccess, nil, "example.com."},
		{"nx.sub.example.com.", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil, "example.com."},
		{"empty.example.com.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, nil, "example.com."},
		{"example.com.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, nil, "example.com."},
		{"fail.example.com.", dnsmessage.TypeA, dnsmessage.RCodeServerFailure, nil, ""},
		{"refused.example.com.", dnsmessage.TypeA, dnsmessage.RCodeRefused, nil, ""},
	} {
		t.Run(tc.name+" "+tc.qtype.String(), func(t *testing.T) {
			got := parseAnswer(t, udpExchange(t, srv.Addr, queryType(t, tc.name, tc.qtype)))
			if got.hdr.RCode != tc.rcode {
				t.Errorf("rcode %v, want %v", got.hdr.RCode, tc.rcode)
			}
			if !got.hdr.Response || !got.hdr.Authoritative || !got.hdr.RecursionDesired || got.hdr.ID != 1 {
				t.Errorf("header %+v: want an authoritative response echoing ID 1 and RD", got.hdr)
			}
			if !slices.Equal(got.records, tc.records) {
				t.Errorf("answers %q, want %q", got.records, tc.records)
			}
			if got.soa != tc.soa {
				t.Errorf("authority SOA %q, want %q", got.soa, tc.soa)
			}
		})
	}
}

// TestBuildRejectsBadCNAME: a CNAME too long to be a name fails the build,
// which the server turns into a dropped query rather than a malformed answer.
func TestBuildRejectsBadCNAME(t *testing.T) {
	q := Query{Name: "www.example.com", Type: dnsmessage.TypeA}
	question := dnsmessage.Question{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if _, err := build(dnsmessage.Header{ID: 1}, question, q, Reply{CNAME: strings.Repeat("a.", 200)}); err == nil {
		t.Error("build accepted a 400-byte CNAME")
	}
}
