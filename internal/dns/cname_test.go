package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"golang.org/x/net/dns/dnsmessage"
)

// TestCNAMEOneQuery covers #249: -type CNAME sends one CNAME query a name,
// reads the alias from it, and maps each RCODE onto the outcome Go's
// LookupCNAME gave.
func TestCNAMEOneQuery(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "blog.example.com":
			return dnstest.Reply{CNAME: "ghost.example.net"}
		case "www.example.com":
			return dnstest.Reply{A: []string{"192.0.2.1"}} // NODATA for CNAME
		case "broken.example.com":
			return dnstest.ServFail
		case "busy.example.com":
			return dnstest.Refused
		case "big.example.com":
			return dnstest.Reply{CNAME: "edge.example.net", Truncate: true}
		}
		return dnstest.NXDomain
	})
	l := Lookup{Resolver: NewResolver(time.Second, srv.Addr), Timeout: time.Second, Attempts: 1, Types: []string{"CNAME"}}
	for _, tc := range []struct {
		name    string
		want    string // the CNAME target, if any
		outcome Outcome
		queries int64 // CNAME queries on the wire
	}{
		{"blog.example.com", "ghost.example.net", OutcomeFound, 1},
		{"www.example.com", "", OutcomeNXDomain, 1},
		{"nope.example.com", "", OutcomeNXDomain, 1},
		{"broken.example.com", "", OutcomeOther, 1},
		{"busy.example.com", "", OutcomeRefused, 1},
		{"big.example.com", "edge.example.net", OutcomeFound, 2}, // UDP, then TCP
	} {
		recs, outcome := l.Resolve(context.Background(), tc.name)
		if outcome != tc.outcome {
			t.Errorf("%s: outcome %v, want %v", tc.name, outcome, tc.outcome)
		}
		if tc.want != "" && (len(recs) != 1 || recs[0] != (Record{Type: "CNAME", Value: tc.want})) {
			t.Errorf("%s: records %v, want CNAME %s", tc.name, recs, tc.want)
		}
		for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			if n := srv.QueriesFor(tc.name, typ); n != 0 {
				t.Errorf("%s: %d %v queries; a CNAME lookup sends only CNAME", tc.name, n, typ)
			}
		}
		if n := srv.QueriesFor(tc.name, dnsmessage.TypeCNAME); n != tc.queries {
			t.Errorf("%s: %d CNAME queries, want %d", tc.name, n, tc.queries)
		}
	}
}

// TestCNAMETimeout: a server that never answers is a timeout, not a
// negative, and a cancelled scan is cancelled.
func TestCNAMETimeout(t *testing.T) {
	r := NewResolver(time.Second, startBlackHole(t))
	_, err := lookupType(contextWithTimeout(t, 100*time.Millisecond), r, "slow.example.com.", "slow.example.com", "CNAME")
	if Classify(err) != OutcomeTimeout {
		t.Errorf("unanswered CNAME query: %v (%v), want a timeout", err, Classify(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lookupType(ctx, r, "slow.example.com.", "slow.example.com", "CNAME"); Classify(err) != OutcomeCanceled {
		t.Errorf("cancelled CNAME lookup: %v (%v), want canceled", err, Classify(err))
	}
}

// TestCNAMEChain: the end of an alias chain in one answer is the target,
// as with Go's LookupCNAME.
func TestCNAMEChain(t *testing.T) {
	msg := dnsmessage.Message{Answers: []dnsmessage.Resource{
		cnameRR(t, "b.example.com.", "c.example.net."),
		cnameRR(t, "a.example.com.", "b.example.com."),
	}}
	if got := canonicalName(&msg, "A.example.com."); got != "c.example.net." {
		t.Errorf("canonicalName = %q, want c.example.net.", got)
	}
	if got := canonicalName(&dnsmessage.Message{}, "a.example.com."); got != "a.example.com." {
		t.Errorf("no alias: canonicalName = %q, want the name itself", got)
	}
	loop := dnsmessage.Message{Answers: []dnsmessage.Resource{
		cnameRR(t, "x.example.com.", "y.example.com."),
		cnameRR(t, "y.example.com.", "x.example.com."),
	}}
	_ = canonicalName(&loop, "x.example.com.") // must return, not spin
}

// scriptedUDP is a UDP DNS server for one test: for each query it sends the
// datagrams script returns, in order. It returns its socket, so a test can
// also send a datagram to a client as if it were a late answer, and the
// number of queries it has read.
func scriptedUDP(t *testing.T, script func(h dnsmessage.Header, q dnsmessage.Question) [][]byte) (net.PacketConn, *atomic.Int64) {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	var queries atomic.Int64
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			queries.Add(1)
			for _, msg := range script(h, q) {
				_, _ = pc.WriteTo(msg, from)
			}
		}
	}()
	return pc, &queries
}

// cnameMsg builds a DNS message with header hdr and question q, and, when
// target is set, one CNAME record from owner to target in the answer.
func cnameMsg(t *testing.T, hdr dnsmessage.Header, q dnsmessage.Question, owner dnsmessage.Name, target string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, hdr)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Error(err)
	}
	_ = b.Question(q)
	if target != "" {
		_ = b.StartAnswers()
		_ = b.CNAMEResource(dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)})
	}
	msg, err := b.Finish()
	if err != nil {
		t.Error(err)
	}
	return msg
}

// TestCNAMESkipsRepliesToOtherQueries covers #305: over UDP, a datagram that
// is not the answer to the query just sent (another ID, another question, a
// query, or not DNS at all) is skipped, and the answer that follows it is the
// one reported. Each wrong reply carries an alias for the queried name, so
// accepting it would report the wrong target.
func TestCNAMESkipsRepliesToOtherQueries(t *testing.T) {
	const right, wrong = "right.example.net.", "wrong.example.net."
	for _, tc := range []struct {
		name string
		bad  func(h dnsmessage.Header, q dnsmessage.Question) []byte
	}{
		{"another ID", func(h dnsmessage.Header, q dnsmessage.Question) []byte {
			return cnameMsg(t, dnsmessage.Header{ID: h.ID + 1, Response: true}, q, q.Name, wrong)
		}},
		{"another name", func(h dnsmessage.Header, q dnsmessage.Question) []byte {
			other := q
			other.Name = dnsmessage.MustNewName("other.example.com.")
			return cnameMsg(t, dnsmessage.Header{ID: h.ID, Response: true}, other, q.Name, wrong)
		}},
		{"another type", func(h dnsmessage.Header, q dnsmessage.Question) []byte {
			other := q
			other.Type = dnsmessage.TypeA
			return cnameMsg(t, dnsmessage.Header{ID: h.ID, Response: true}, other, q.Name, wrong)
		}},
		{"a query, not a response", func(h dnsmessage.Header, q dnsmessage.Question) []byte {
			return cnameMsg(t, dnsmessage.Header{ID: h.ID}, q, q.Name, wrong)
		}},
		{"no question", func(h dnsmessage.Header, _ dnsmessage.Question) []byte {
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
			msg, err := b.Finish()
			if err != nil {
				t.Error(err)
			}
			return msg
		}},
		{"not a DNS message", func(dnsmessage.Header, dnsmessage.Question) []byte { return []byte{1, 2, 3} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, queries := scriptedUDP(t, func(h dnsmessage.Header, q dnsmessage.Question) [][]byte {
				return [][]byte{tc.bad(h, q), cnameMsg(t, dnsmessage.Header{ID: h.ID, Response: true}, q, q.Name, right)}
			})
			r := NewResolver(5*time.Second, srv.LocalAddr().String())
			defer CloseIdleConnections(r)
			recs, outcome := Lookup{Resolver: r, Timeout: 5 * time.Second, Attempts: 1, Types: []string{"CNAME"}}.Resolve(context.Background(), "blog.example.com")
			if outcome != OutcomeFound || len(recs) != 1 || recs[0] != (Record{Type: "CNAME", Value: "right.example.net"}) {
				t.Errorf("outcome %v, records %v; want CNAME right.example.net", outcome, recs)
			}
			if n := queries.Load(); n != 1 {
				t.Errorf("%d queries on the wire, want 1", n)
			}
		})
	}
}

// TestCNAMEOnlyMismatchedRepliesIsTimeout covers #305: replies that never
// match the query do not end the wait; the lookup times out, which is not a
// negative answer.
func TestCNAMEOnlyMismatchedRepliesIsTimeout(t *testing.T) {
	srv, _ := scriptedUDP(t, func(h dnsmessage.Header, q dnsmessage.Question) [][]byte {
		return [][]byte{cnameMsg(t, dnsmessage.Header{ID: h.ID + 1, Response: true}, q, q.Name, "wrong.example.net.")}
	})
	r := NewResolver(300*time.Millisecond, srv.LocalAddr().String())
	defer CloseIdleConnections(r)
	recs, outcome := Lookup{Resolver: r, Timeout: 300 * time.Millisecond, Attempts: 1, Types: []string{"CNAME"}}.Resolve(context.Background(), "blog.example.com")
	if outcome != OutcomeTimeout || len(recs) != 0 {
		t.Errorf("outcome %v, records %v; want a timeout and no records", outcome, recs)
	}
}

// TestCNAMEPooledSocketSkipsStaleReply covers #305: as
// TestPooledSocketSkipsStaleReply, for the CNAME client. A late CNAME answer
// to an earlier query waits in the pooled socket; the next lookup on that
// socket gets its own answer, and a stale REFUSED does not turn that lookup's
// own failure into refused.
func TestCNAMEPooledSocketSkipsStaleReply(t *testing.T) {
	srv, _ := scriptedUDP(t, func(h dnsmessage.Header, q dnsmessage.Question) [][]byte {
		if q.Name.String() == "www.example.com." && q.Type == dnsmessage.TypeCNAME {
			return [][]byte{cnameMsg(t, dnsmessage.Header{ID: h.ID, Response: true}, q, q.Name, "edge.example.net.")}
		}
		return [][]byte{cnameMsg(t, dnsmessage.Header{ID: h.ID, Response: true, RCode: dnsmessage.RCodeServerFailure}, q, q.Name, "")}
	})
	r := NewResolver(5*time.Second, srv.LocalAddr().String())
	defer CloseIdleConnections(r)
	d := dialerOf(t, r)
	ctx := context.Background()
	l := Lookup{Resolver: r, Timeout: 5 * time.Second, Attempts: 1, Types: []string{"CNAME"}}

	// stale queues an answer to a query never sent on the one pooled socket.
	stale := func(rcode dnsmessage.RCode, target string) {
		t.Helper()
		if len(d.idle) != 1 {
			t.Fatalf("%d pooled sockets, want 1", len(d.idle))
		}
		u := <-d.idle
		d.idle <- u
		q := dnsmessage.Question{Name: dnsmessage.MustNewName("old.example.com."), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}
		if _, err := srv.WriteTo(cnameMsg(t, dnsmessage.Header{ID: 0xBEEF, Response: true, RCode: rcode}, q, q.Name, target), u.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond) // let it land in the socket's buffer
	}

	if _, o := l.Resolve(ctx, "www.example.com"); o != OutcomeFound {
		t.Fatalf("warm-up lookup: %v", o)
	}
	stale(dnsmessage.RCodeSuccess, "stale.example.net.")
	recs, o := l.Resolve(ctx, "www.example.com")
	if o != OutcomeFound || len(recs) != 1 || recs[0] != (Record{Type: "CNAME", Value: "edge.example.net"}) {
		t.Fatalf("www after a stale reply: %v %v, want CNAME edge.example.net", o, recs)
	}
	stale(dnsmessage.RCodeRefused, "")
	if _, o := l.Resolve(ctx, "fail.example.com"); o != OutcomeOther {
		t.Errorf("SERVFAIL after a stale REFUSED: %v, want other (not refused)", o)
	}
}

// TestCNAMEOverTCPRejectsBadReplies covers #305: after a truncated UDP
// answer the query is asked again over TCP, where a reply that does not
// match, does not parse, or stops mid-message is an error, never an answer.
func TestCNAMEOverTCPRejectsBadReplies(t *testing.T) {
	const name = "big.example.com."
	q := dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}
	for _, tc := range []struct {
		name  string
		serve func(id uint16, conn net.Conn)
		want  string // text in the error, when is is nil
		is    error
	}{
		{name: "another ID", want: "reply does not match the query", serve: func(id uint16, conn net.Conn) {
			writeFramed(conn, cnameMsg(t, dnsmessage.Header{ID: id + 1, Response: true}, q, q.Name, "wrong.example.net."))
		}},
		{name: "not a DNS message", serve: func(_ uint16, conn net.Conn) { writeFramed(conn, []byte{1, 2, 3}) }},
		{name: "closed in the length prefix", is: io.ErrUnexpectedEOF, serve: func(_ uint16, conn net.Conn) { _, _ = conn.Write([]byte{0}) }},
		{name: "closed mid-message", is: io.ErrUnexpectedEOF, serve: func(_ uint16, conn net.Conn) { _, _ = conn.Write([]byte{0, 200, 1, 2, 3}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			udp, udpQueries := scriptedUDP(t, func(h dnsmessage.Header, q dnsmessage.Question) [][]byte {
				return [][]byte{cnameMsg(t, dnsmessage.Header{ID: h.ID, Response: true, Truncated: true}, q, q.Name, "")}
			})
			var tcpQueries atomic.Int64
			tcp := tcpServer(t, func(id uint16, conn net.Conn) {
				tcpQueries.Add(1)
				tc.serve(id, conn)
			})
			r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				addr := udp.LocalAddr().String()
				if network == "tcp" {
					addr = tcp
				}
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}}
			got, err := lookupCNAME(contextWithTimeout(t, 5*time.Second), r, name)
			if err == nil {
				t.Fatalf("lookupCNAME = %q, want an error", got)
			}
			if o := Classify(err); o != OutcomeOther {
				t.Errorf("outcome %v (%v), want other", o, err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("err = %v, want %v", err, tc.is)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
			if u, c := udpQueries.Load(), tcpQueries.Load(); u != 1 || c != 1 {
				t.Errorf("%d UDP and %d TCP queries, want 1 and 1", u, c)
			}
		})
	}
}

// timeoutError is a net.Error that reports a timeout, as a read past a
// connection's deadline does.
type timeoutError struct{}

func (timeoutError) Error() string   { return "read: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestDNSErrorFor covers #305: a transport timeout under a live context is a
// timeout, and any other transport error is "other" with the cause kept.
func TestDNSErrorFor(t *testing.T) {
	ctx := context.Background()
	err := dnsErrorFor(ctx, "www.example.com", fmt.Errorf("exchange: %w", timeoutError{}))
	var de *net.DNSError
	if !errors.As(err, &de) || !de.IsTimeout || de.Name != "www.example.com" {
		t.Errorf("timeout: %#v, want a *net.DNSError with IsTimeout for the name", err)
	}
	if o := Classify(err); o != OutcomeTimeout {
		t.Errorf("timeout: outcome %v, want timeout", o)
	}

	cause := errors.New("connection reset")
	err = dnsErrorFor(ctx, "www.example.com", cause)
	if !errors.As(err, &de) || de.IsTimeout || de.IsNotFound || de.Name != "www.example.com" {
		t.Errorf("plain error: %#v, want a *net.DNSError that is neither a timeout nor not found", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("plain error: %v does not unwrap to its cause", err)
	}
	if o := Classify(err); o != OutcomeOther {
		t.Errorf("plain error: outcome %v, want other", o)
	}
}

// TestCNAMEInvalidNameSendsNoQuery covers #305: a name that cannot be put in
// a DNS message is never sent. One too long for dnsmessage.NewName is
// reported as not found without a connection.
func TestCNAMEInvalidNameSendsNoQuery(t *testing.T) {
	var dials, writes atomic.Int64
	srv, queries := scriptedUDP(t, func(h dnsmessage.Header, q dnsmessage.Question) [][]byte {
		return [][]byte{cnameMsg(t, dnsmessage.Header{ID: h.ID, Response: true}, q, q.Name, "wrong.example.net.")}
	})
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		c, err := d.DialContext(ctx, network, srv.LocalAddr().String())
		if err != nil {
			return nil, err
		}
		return &writeCountingConn{Conn: c, writes: &writes}, nil
	}}

	long := strings.Repeat("a.", 130) + "example.com." // over 255 bytes
	_, err := lookupCNAME(contextWithTimeout(t, 5*time.Second), r, long)
	var de *net.DNSError
	if !errors.As(err, &de) || !de.IsNotFound || Classify(err) != OutcomeNXDomain {
		t.Errorf("name over 255 bytes: %v, want a not-found error", err)
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("name over 255 bytes: %d connections, want 0", n)
	}

	// A label over 63 bytes, or an empty one, passes NewName; it is not
	// found either, without a connection (#344).
	for _, name := range []string{strings.Repeat("a", 64) + ".example.com.", "a..example.com."} {
		_, err := lookupCNAME(contextWithTimeout(t, 5*time.Second), r, name)
		if !errors.As(err, &de) || !de.IsNotFound || Classify(err) != OutcomeNXDomain {
			t.Errorf("%s: %v, want a not-found error", name, err)
		}
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("invalid labels: %d connections, want 0", n)
	}
	if w, q := writes.Load(), queries.Load(); w != 0 || q != 0 {
		t.Errorf("invalid names: %d writes and %d queries on the wire, want 0", w, q)
	}
}

// TestCNAMEReadBuffer covers #321: a CNAME lookup reads a UDP answer into a
// buffer sized for the advertised EDNS(0) payload and a TCP answer into its
// announced length, not a 64 KiB buffer per lookup.
func TestCNAMEReadBuffer(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.Name == "big.example.com" {
			return dnstest.Reply{CNAME: "edge.example.net", Truncate: true} // UDP, then TCP
		}
		return dnstest.Reply{CNAME: "ghost.example.net"}
	})
	r := NewResolver(time.Second, srv.Addr)
	for _, name := range []string{"blog.example.com.", "big.example.com."} {
		lookup := func() {
			if _, err := lookupCNAME(contextWithTimeout(t, 5*time.Second), r, name); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		lookup() // warm up
		const runs = 20
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for range runs {
			lookup()
		}
		runtime.ReadMemStats(&after)
		// The client and the in-process server together; a 64 KiB read
		// buffer alone would be far over this.
		if per := (after.TotalAlloc - before.TotalAlloc) / runs; per > 16<<10 {
			t.Errorf("%s: %d bytes allocated per lookup, want at most 16 KiB", name, per)
		}
	}
}

// writeCountingConn counts the writes on a connection.
type writeCountingConn struct {
	net.Conn
	writes *atomic.Int64
}

func (c *writeCountingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

func cnameRR(t *testing.T, owner, target string) dnsmessage.Resource {
	t.Helper()
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)},
	}
}

func contextWithTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}
