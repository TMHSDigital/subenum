package dns

import (
	"context"
	"net"
	"testing"
	"time"
	"weak"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"golang.org/x/net/dns/dnsmessage"
)

// TestUDPSocketsAreReused covers #180: a closed UDP conn goes back to the
// pool and the next query uses the same socket instead of opening one.
func TestUDPSocketsAreReused(t *testing.T) {
	srv := dnstest.Start(t, func(dnstest.Query) dnstest.Reply { return dnstest.NXDomain })
	d := newUDPDialer(srv.Addr, time.Second)
	defer d.closeIdle()
	c1, err := d.dial(context.Background(), "udp")
	if err != nil {
		t.Fatal(err)
	}
	first := c1.LocalAddr().String()
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
	c2, err := d.dial(context.Background(), "udp")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	if got := c2.LocalAddr().String(); got != first {
		t.Errorf("second dial used %s, want the pooled socket %s", got, first)
	}
	if _, ok := c2.(net.PacketConn); !ok {
		t.Error("pooled UDP conn is not a net.PacketConn; Go's resolver would frame it as TCP")
	}

	// A socket that failed other than by timing out is not reused.
	c2.(*pooledUDPConn).bad = true
	_ = c2.Close()
	if n := len(d.idle); n != 0 {
		t.Errorf("%d sockets pooled after a failed one closed, want 0", n)
	}
}

// rawServer is a minimal UDP DNS server: www.example.com has A 192.0.2.1,
// every other name gets SERVFAIL. Unlike dnstest it exposes its socket, so a
// test can send a datagram to a client as if it were a late answer.
func rawServer(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
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
			rcode, a := dnsmessage.RCodeServerFailure, false
			if q.Name.String() == "www.example.com." && q.Type == dnsmessage.TypeA {
				rcode, a = dnsmessage.RCodeSuccess, true
			}
			msg := reply(t, h.ID, q, rcode, a)
			_, _ = pc.WriteTo(msg, from)
		}
	}()
	return pc
}

func reply(t *testing.T, id uint16, q dnsmessage.Question, rcode dnsmessage.RCode, withA bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RCode: rcode, RecursionAvailable: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Error(err)
	}
	_ = b.Question(q)
	if withA {
		_ = b.StartAnswers()
		_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})
	}
	msg, err := b.Finish()
	if err != nil {
		t.Error(err)
	}
	return msg
}

// TestPooledSocketSkipsStaleReply: a late answer to an earlier query can
// wait in a pooled socket. The next lookup on that socket must skip it, and
// a stale REFUSED must not turn that lookup's own failure into refused.
func TestPooledSocketSkipsStaleReply(t *testing.T) {
	srv := rawServer(t)
	r := NewResolver(2*time.Second, srv.LocalAddr().String())
	defer CloseIdleConnections(r)
	v, _ := pooledDialers.Load(weak.Make(r))
	d := v.(*udpDialer)
	ctx := context.Background()
	a := []string{"A"}

	// stale queues a REFUSED for a query never sent on the one pooled socket.
	stale := func() {
		t.Helper()
		if len(d.idle) != 1 {
			t.Fatalf("%d pooled sockets, want 1", len(d.idle))
		}
		u := <-d.idle
		d.idle <- u
		q := dnsmessage.Question{Name: dnsmessage.MustNewName("old.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
		if _, err := srv.WriteTo(reply(t, 0xBEEF, q, dnsmessage.RCodeRefused, false), u.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond) // let it land in the socket's buffer
	}

	if _, o := (Lookup{Resolver: r, Timeout: 2 * time.Second, Attempts: 1, Types: a}).Resolve(ctx, "www.example.com"); o != OutcomeFound {
		t.Fatalf("warm-up lookup: %v", o)
	}
	stale()
	recs, o := Lookup{Resolver: r, Timeout: 2 * time.Second, Attempts: 1, Types: a}.Resolve(ctx, "www.example.com")
	if o != OutcomeFound || len(recs) != 1 || recs[0].Value != "192.0.2.1" {
		t.Fatalf("www after a stale reply: %v %v, want 192.0.2.1", o, recs)
	}
	stale()
	if _, o := (Lookup{Resolver: r, Timeout: 2 * time.Second, Attempts: 1, Types: a}).Resolve(ctx, "fail.example.com"); o != OutcomeOther {
		t.Errorf("SERVFAIL after a stale REFUSED: %v, want other (not refused)", o)
	}
}
