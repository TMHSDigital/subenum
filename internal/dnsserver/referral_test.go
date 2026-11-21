package dnsserver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestReferral covers #406: the handler sees whether a query asked for
// recursion, and a Referral reply is a non-authoritative NOERROR with no
// answer and the delegation's NS records, owned by ReferralZone, in the
// authority section.
func TestReferral(t *testing.T) {
	var recursive, plain atomic.Int32
	srv, err := Listen(Options{}, func(q Query) Reply {
		if q.Recursive {
			recursive.Add(1)
		} else {
			plain.Add(1)
		}
		return Reply{A: []string{"192.0.2.1"}, Referral: []string{"ns1.gone.example", "ns2.gone.example."}, ReferralZone: "old.example.test"}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	// Go's resolver asks for recursion.
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Addr)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if addrs, err := r.LookupHost(ctx, "www.old.example.test"); err == nil {
		t.Errorf("a referral answered addresses %v", addrs)
	}
	if recursive.Load() == 0 {
		t.Error("the resolver's queries were not seen as recursive")
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("www.old.example.test."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	resp := exchangeUDP(t, srv.Addr, msg)
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.Authoritative || h.RCode != dnsmessage.RCodeSuccess || h.RecursionDesired {
		t.Errorf("header %+v, want a non-authoritative NOERROR echoing RD clear", h)
	}
	_ = p.SkipAllQuestions()
	if answers, _ := p.AllAnswers(); len(answers) != 0 {
		t.Errorf("answers %v, want none", answers)
	}
	auth, err := p.AllAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, rr := range auth {
		ns, ok := rr.Body.(*dnsmessage.NSResource)
		if !ok || rr.Header.Name.String() != "old.example.test." {
			t.Errorf("authority record %v, want NS owned by old.example.test.", rr)
			continue
		}
		got = append(got, ns.NS.String())
	}
	if len(got) != 2 || got[0] != "ns1.gone.example." || got[1] != "ns2.gone.example." {
		t.Errorf("referral = %v", got)
	}
	if plain.Load() != 1 {
		t.Errorf("%d non-recursive queries seen, want 1", plain.Load())
	}
}

// exchangeUDP sends msg to addr and returns the answer.
func exchangeUDP(t *testing.T, addr string, msg []byte) []byte {
	t.Helper()
	var d net.Dialer
	conn, err := d.DialContext(context.Background(), "udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}
