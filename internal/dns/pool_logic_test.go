package dns

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// Fast, in-package tests of the pool's trust model (#168): selection,
// benching, contradictions, canaries and second opinions. Each member is a
// loopback dnstest server, so a case runs in milliseconds.

// countingDNS starts a table-driven test server that counts the queries it
// receives.
func countingDNS(t *testing.T, table map[string]testReply) (string, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	s := &testDNS{table: table}
	s.Server = dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		n.Add(1)
		return s.answer(q)
	})
	s.addr = s.Addr
	return s.addr, &n
}

var typesA = []string{"A"}

const poolTestTimeout = 2 * time.Second

func TestPoolResolveWithEveryMemberFlagged(t *testing.T) {
	p := NewPool([]string{"192.0.2.1:53", "192.0.2.2:53"}, time.Second)
	for _, m := range p.members {
		m.stats.Flagged = true
	}
	a := p.Resolve(context.Background(), Lookup{Timeout: time.Second, Attempts: 3, Types: typesA}, "www.example.com")
	if !a.NoResolver || a.Outcome != OutcomeOther {
		t.Fatalf("answer = %+v, want NoResolver", a)
	}
	for _, st := range p.Stats() {
		if st.Lookups != 0 {
			t.Fatalf("flagged member %s counted %d lookups", st.Addr, st.Lookups)
		}
	}
}

func TestPoolResolveCanceledContext(t *testing.T) {
	addr, queries := countingDNS(t, map[string]testReply{"*": {A: "192.0.2.10"}})
	p := NewPool([]string{addr}, poolTestTimeout)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a := p.Resolve(ctx, Lookup{Timeout: poolTestTimeout, Attempts: 3, Types: typesA}, "www.example.com"); a.Outcome != OutcomeCanceled {
		t.Fatalf("outcome = %v, want canceled", a.Outcome)
	}
	if n := queries.Load(); n != 0 {
		t.Fatalf("%d queries sent with a cancelled context", n)
	}
	if st := p.Stats()[0]; st.Lookups != 0 {
		t.Fatalf("cancelled lookup counted: %+v", st)
	}
}

func TestPoolPickHealthy(t *testing.T) {
	p := NewPool([]string{"192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"}, time.Second)
	now := time.Unix(1000, 0)
	p.now = func() time.Time { return now }
	a, b, c := p.members[0], p.members[1], p.members[2]

	b.stats.Flagged = true
	c.until = now.Add(poolBenchFor)
	for range 4 {
		if got := p.pickHealthy(nil); got != a {
			t.Fatalf("pickHealthy = %s, want the only healthy member", got.Addr)
		}
	}
	if got := p.pickHealthy(a); got != nil {
		t.Fatalf("pickHealthy(avoid the healthy one) = %s, want nil (others flagged or benched)", got.Addr)
	}

	// A benched member is eligible exactly when its bench ends.
	now = c.until.Add(-time.Nanosecond)
	if got := p.pickHealthy(a); got != nil {
		t.Fatalf("benched member returned before its bench ended: %s", got.Addr)
	}
	now = c.until
	if got := p.pickHealthy(a); got != c {
		t.Fatalf("pickHealthy at bench expiry = %v, want %s", got, c.Addr)
	}
	for range 6 {
		if p.pickHealthy(nil) == b {
			t.Fatal("flagged member returned")
		}
	}
}

func TestPoolDisagreeFlagsAfterRepeatedContradictions(t *testing.T) {
	p := NewPool([]string{"192.0.2.1:53", "192.0.2.2:53"}, time.Second)
	liar, other := p.members[0], p.members[1]

	// The trusted resolver confirms a name the liar hid behind NXDOMAIN.
	p.Disagree(PoolAnswer{member: other, contradicted: liar}, OutcomeFound)
	// The trusted resolver denies a hit the liar injected.
	p.Disagree(PoolAnswer{member: liar}, OutcomeNXDomain)
	if st := p.Stats()[0]; st.Contradicted != 2 || st.Flagged {
		t.Fatalf("after 2 contradictions: %+v", st)
	}
	// Outcomes that prove nothing, and answers with no member, change nothing.
	p.Disagree(PoolAnswer{member: liar}, OutcomeTimeout)
	p.Disagree(PoolAnswer{}, OutcomeFound)
	p.Disagree(PoolAnswer{}, OutcomeNXDomain)
	if st := p.Stats()[0]; st.Contradicted != 2 {
		t.Fatalf("non-contradicting outcomes counted: %+v", st)
	}

	p.Disagree(PoolAnswer{member: liar}, OutcomeNXDomain)
	if st := p.Stats()[0]; st.Contradicted != poolFlagAfter || !st.Flagged {
		t.Fatalf("after %d contradictions: %+v, want flagged", poolFlagAfter, st)
	}
	if st := p.Stats()[1]; st.Contradicted != 0 {
		t.Fatalf("honest member counted: %+v", st)
	}
	for range 4 {
		if p.pick(nil) == liar {
			t.Fatal("flagged member picked")
		}
	}
}

func TestPoolAddCanaryDedupesAndCaps(t *testing.T) {
	p := NewPool([]string{"192.0.2.1:53"}, time.Second)
	if p.Size() != 1 {
		t.Fatalf("Size = %d", p.Size())
	}
	if got := p.canary(); got != "" {
		t.Fatalf("canary with none known = %q", got)
	}
	p.AddCanary("a.example.com")
	p.AddCanary("a.example.com")
	p.AddCanary("b.example.com")
	if got := []string{p.canary(), p.canary(), p.canary()}; got[0] != "a.example.com" || got[1] != "b.example.com" || got[2] != "a.example.com" {
		t.Fatalf("canary rotation = %v", got)
	}
	for i := range poolMaxCanaries * 2 {
		p.AddCanary(fmt.Sprintf("n%d.example.com", i))
	}
	if len(p.canaries) != poolMaxCanaries {
		t.Fatalf("%d canaries kept, want the cap %d", len(p.canaries), poolMaxCanaries)
	}
}

func TestPoolCanaryCheck(t *testing.T) {
	table := map[string]testReply{"canary.example.com": {A: "192.0.2.10"}, "www.example.com": {A: "192.0.2.11"}}
	ctx := context.Background()

	t.Run("no canaries sends no check", func(t *testing.T) {
		addr, queries := countingDNS(t, table)
		p := NewPool([]string{addr}, poolTestTimeout)
		p.Resolve(ctx, Lookup{Timeout: poolTestTimeout, Attempts: 1, Types: typesA}, "www.example.com")
		if n := queries.Load(); n != 1 {
			t.Fatalf("%d queries, want only the lookup", n)
		}
		if st := p.Stats()[0]; st.Canaries != 0 {
			t.Fatalf("canary counted: %+v", st)
		}
	})

	t.Run("correct answer earns trust", func(t *testing.T) {
		addr, queries := countingDNS(t, table)
		p := NewPool([]string{addr}, poolTestTimeout)
		p.AddCanary("canary.example.com")
		if a := p.Resolve(ctx, Lookup{Timeout: poolTestTimeout, Attempts: 1, Types: typesA}, "www.example.com"); a.Outcome != OutcomeFound {
			t.Fatalf("outcome = %v", a.Outcome)
		}
		if n := queries.Load(); n != 2 {
			t.Fatalf("%d queries, want canary + lookup", n)
		}
		st := p.Stats()[0]
		if st.Canaries != 1 || st.Contradicted != 0 || !p.members[0].trusted {
			t.Fatalf("after a correct canary: %+v trusted=%v", st, p.members[0].trusted)
		}
		// A trusted member is not checked again until poolCanaryEvery lookups.
		p.Resolve(ctx, Lookup{Timeout: poolTestTimeout, Attempts: 1, Types: typesA}, "www.example.com")
		if n := queries.Load(); n != 3 {
			t.Fatalf("%d queries, want no second canary check", n)
		}
	})

	t.Run("hidden canary is a contradiction", func(t *testing.T) {
		addr, _ := countingDNS(t, map[string]testReply{"www.example.com": {A: "192.0.2.11"}})
		p := NewPool([]string{addr}, poolTestTimeout)
		p.AddCanary("canary.example.com")
		p.Resolve(ctx, Lookup{Timeout: poolTestTimeout, Attempts: 1, Types: typesA}, "www.example.com")
		st := p.Stats()[0]
		if st.Canaries != 1 || st.Contradicted != 1 || p.members[0].trusted {
			t.Fatalf("after a hidden canary: %+v trusted=%v", st, p.members[0].trusted)
		}
	})
}

func TestPoolSecondOpinion(t *testing.T) {
	ctx := context.Background()
	honestTable := map[string]testReply{"www.example.com": {A: "192.0.2.11"}}

	t.Run("untrusted NXDOMAIN is overruled by another member", func(t *testing.T) {
		liarAddr, _ := countingDNS(t, map[string]testReply{})
		honestAddr, _ := countingDNS(t, honestTable)
		p := NewPool([]string{liarAddr, honestAddr}, poolTestTimeout)
		a := p.Resolve(ctx, Lookup{Timeout: poolTestTimeout, Attempts: 1, Types: typesA}, "www.example.com")
		if a.Outcome != OutcomeFound || a.Addr != honestAddr || a.contradicted != p.members[0] {
			t.Fatalf("answer = %+v, want the honest member's hit with the liar contradicted", a)
		}
		if st := p.Stats(); st[0].Lookups != 1 || st[1].Lookups != 1 {
			t.Fatalf("lookups = %d, %d; want one each", st[0].Lookups, st[1].Lookups)
		}
		p.Disagree(a, OutcomeFound)
		if st := p.Stats()[0]; st.Contradicted != 1 {
			t.Fatalf("liar not contradicted: %+v", st)
		}
	})

	t.Run("trusted NXDOMAIN is taken at face value", func(t *testing.T) {
		nxAddr, _ := countingDNS(t, map[string]testReply{})
		otherAddr, otherQueries := countingDNS(t, honestTable)
		p := NewPool([]string{nxAddr, otherAddr}, poolTestTimeout)
		p.members[0].trusted = true
		if a := p.Resolve(ctx, Lookup{Timeout: poolTestTimeout, Attempts: 1, Types: typesA}, "www.example.com"); a.Outcome != OutcomeNXDomain || a.Addr != nxAddr {
			t.Fatalf("answer = %+v, want the trusted NXDOMAIN", a)
		}
		if n := otherQueries.Load(); n != 0 {
			t.Fatalf("second opinion asked of a trusted member's NXDOMAIN (%d queries)", n)
		}
	})

	t.Run("single member has no second opinion", func(t *testing.T) {
		addr, queries := countingDNS(t, map[string]testReply{})
		p := NewPool([]string{addr}, poolTestTimeout)
		if a := p.Resolve(ctx, Lookup{Timeout: poolTestTimeout, Attempts: 1, Types: typesA}, "www.example.com"); a.Outcome != OutcomeNXDomain {
			t.Fatalf("outcome = %v", a.Outcome)
		}
		if n := queries.Load(); n != 1 {
			t.Fatalf("%d queries, want 1", n)
		}
	})

	t.Run("agreeing NXDOMAIN stays NXDOMAIN", func(t *testing.T) {
		a1, _ := countingDNS(t, map[string]testReply{})
		a2, _ := countingDNS(t, map[string]testReply{})
		p := NewPool([]string{a1, a2}, poolTestTimeout)
		a := p.Resolve(ctx, Lookup{Timeout: poolTestTimeout, Attempts: 1, Types: typesA}, "www.example.com")
		if a.Outcome != OutcomeNXDomain || a.Addr != a1 || a.contradicted != nil {
			t.Fatalf("answer = %+v, want the first NXDOMAIN, nobody contradicted", a)
		}
	})
}

func TestPoolResolveRetriesOnAnotherMember(t *testing.T) {
	failAddr, _ := countingDNS(t, map[string]testReply{"*": {ServFail: true}})
	okAddr, _ := countingDNS(t, map[string]testReply{"www.example.com": {A: "192.0.2.11"}})
	p := NewPool([]string{failAddr, okAddr}, poolTestTimeout)

	a := p.Resolve(context.Background(), Lookup{Timeout: poolTestTimeout, Attempts: 2, Types: typesA}, "www.example.com")
	if a.Outcome != OutcomeFound || a.Addr != okAddr {
		t.Fatalf("answer = %+v, want the second member's hit", a)
	}
	if st := p.Stats(); st[0].Failed != 1 || st[1].Found != 1 {
		t.Fatalf("stats = %+v", st)
	}

	// With one attempt the failure is the answer.
	p2 := NewPool([]string{failAddr}, poolTestTimeout)
	if a := p2.Resolve(context.Background(), Lookup{Timeout: poolTestTimeout, Attempts: 1, Types: typesA}, "www.example.com"); a.Outcome == OutcomeFound || a.Outcome == OutcomeNXDomain {
		t.Fatalf("outcome = %v, want a failure", a.Outcome)
	}
}
