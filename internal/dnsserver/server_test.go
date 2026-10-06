package dnsserver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// TestCloseWaitsForHandlers covers #122: Close returns only once no handler
// can still run, including a delayed UDP answer, and it does not hang on a
// stream connection parked on a dropped query.
func TestCloseWaitsForHandlers(t *testing.T) {
	var running, finished atomic.Int32
	srv, err := Listen(Options{}, func(q Query) Reply {
		if q.TCP {
			return Dropped
		}
		running.Add(1)
		defer finished.Add(1)
		return Reply{Delay: 200 * time.Millisecond, A: []string{"192.0.2.1"}}
	})
	if err != nil {
		t.Fatal(err)
	}

	var d net.Dialer
	udp, err := d.DialContext(context.Background(), "udp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	if _, err := udp.Write(query(t, "slow.example.com.")); err != nil {
		t.Fatal(err)
	}
	tcp, err := d.DialContext(context.Background(), "tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	msg := query(t, "dropped.example.com.")
	if _, err := tcp.Write(append([]byte{byte(len(msg) >> 8), byte(len(msg))}, msg...)); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for (running.Load() == 0 || srv.Queries() < 2) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	srv.Close()
	if running.Load() != finished.Load() {
		t.Errorf("Close returned with %d handlers still running", running.Load()-finished.Load())
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("Close took %s; a parked stream connection held it", took)
	}
}

// TestCloseStreamsAfter: a server can close each stream connection after n
// answers, like servers with a per-connection query limit.
func TestCloseStreamsAfter(t *testing.T) {
	srv, err := Listen(Options{}, func(Query) Reply { return Reply{A: []string{"192.0.2.1"}} })
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.CloseStreamsAfter(1)
	var d net.Dialer
	c, err := d.DialContext(context.Background(), "tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	msg := query(t, "www.example.com.")
	framed := append([]byte{byte(len(msg) >> 8), byte(len(msg))}, msg...)
	if _, err := c.Write(framed); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("first answer: %v", err)
	}
	_, _ = c.Write(framed)
	if n, err := c.Read(buf); err == nil {
		t.Errorf("second query on the connection was answered (%d bytes); want it closed", n)
	}
}
