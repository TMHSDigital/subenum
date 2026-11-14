package dns

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestParseResolverList(t *testing.T) {
	got, err := ParseResolverList([]string{"# public", "1.1.1.1", " 8.8.8.8:5353 ", "", "1.1.1.1:53", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.1.1.1:53", "8.8.8.8:5353", "[2001:db8::1]:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if _, err := ParseResolverList([]string{"resolver.example.com"}); err == nil {
		t.Fatal("hostname accepted; resolvers must be IP addresses")
	}
}

func TestPoolRotatesAndBenches(t *testing.T) {
	p := NewPool([]string{"192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"}, time.Second)
	now := time.Unix(0, 0)
	p.now = func() time.Time { return now }

	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		seen[p.pick(nil).Addr]++
	}
	for _, m := range p.members {
		if seen[m.Addr] != 2 {
			t.Fatalf("round-robin uneven: %v", seen)
		}
	}
	if m := p.pick(p.members[0]); m == p.members[0] {
		t.Fatal("pick returned the resolver it was asked to avoid")
	}

	// The first resolver fails every lookup and is benched after the window.
	bad := p.members[0]
	for i := 0; i < poolHealthMinLookups; i++ {
		p.report(bad, OutcomeTimeout)
	}
	if st := p.Stats()[0]; st.Benched != 1 || st.Failed != poolHealthMinLookups {
		t.Fatalf("stats after failures = %+v", st)
	}
	for i := 0; i < 10; i++ {
		if p.pick(nil) == bad {
			t.Fatal("benched resolver picked while others are healthy")
		}
	}
	// Once the bench expires it is back in rotation.
	now = now.Add(poolBenchFor + time.Second)
	back := false
	for i := 0; i < 3; i++ {
		back = back || p.pick(nil) == bad
	}
	if !back {
		t.Fatal("resolver never returned after its bench")
	}
}

// TestQueriesFor checks that the pool books the queries a lookup really
// sends: default types are two, and CNAME is three (#236).
func TestQueriesFor(t *testing.T) {
	for _, tc := range []struct {
		types []string
		want  int
	}{
		{nil, 2},
		{[]string{"A"}, 1},
		{[]string{"A", "AAAA"}, 2},
		{[]string{"A", "AAAA", "CNAME"}, 5},
		{[]string{"NS", "MX", "TXT"}, 3},
	} {
		if got := queriesFor(tc.types); got != tc.want {
			t.Errorf("queriesFor(%v) = %d, want %d", tc.types, got, tc.want)
		}
	}
}

// TestPoolReservesWireQueries resolves through a capped member on a fake
// clock and checks the slots Resolve books (#236): one per wire query the
// lookup sends, not one per record type, so default types book two and a
// CNAME lookup three.
func TestPoolReservesWireQueries(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{"www.example.com": {A: "192.0.2.10", AAAA: "2001:db8::10"}})
	for _, tc := range []struct {
		types []string
		want  int // slots booked by one lookup
	}{
		{nil, 2},
		{[]string{"A", "AAAA", "CNAME"}, 5},
	} {
		p := NewPool([]string{srv.addr}, 2*time.Second)
		p.SetRatePerResolver(10) // 100ms per query
		now := time.Unix(0, 0)
		p.now = func() time.Time { return now }
		p.sleep = func(context.Context, time.Duration) error { return nil }
		m := p.members[0]
		m.trusted = true // no canary or second opinion: only the lookup books
		ans := p.Resolve(context.Background(), Lookup{Timeout: 2 * time.Second, Types: tc.types}, "www.example.com")
		if ans.Outcome != OutcomeFound {
			t.Fatalf("types %v: outcome %v, want found", tc.types, ans.Outcome)
		}
		if want := now.Add(time.Duration(tc.want) * 100 * time.Millisecond); !m.free.Equal(want) {
			t.Errorf("types %v: member free at %v, want %v (%d slots)", tc.types, m.free.Sub(now), want.Sub(now), tc.want)
		}
	}
}

// TestPoolRatePerResolver drives the per-resolver cap (#196) on a fake clock:
// lookups go to members with room first, wait for the one that frees up
// soonest when every cap is spent, and count each spent cap as throttled.
func TestPoolRatePerResolver(t *testing.T) {
	p := NewPool([]string{"192.0.2.1:53", "192.0.2.2:53"}, time.Second)
	p.SetRatePerResolver(2) // one query per 500ms per member
	now := time.Unix(0, 0)
	p.now = func() time.Time { return now }
	var waits []time.Duration
	p.sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	a, b := p.members[0], p.members[1]
	ms := 500 * time.Millisecond

	lookup := func(want *PoolResolver, wantWait time.Duration) {
		t.Helper()
		m := p.pick(nil)
		if m != want {
			t.Fatalf("pick = %s, want %s", m.Addr, want.Addr)
		}
		waits = nil
		if err := p.reserve(context.Background(), m, 1); err != nil {
			t.Fatal(err)
		}
		if len(waits) != 1 || waits[0] != wantWait {
			t.Fatalf("%s waited %v, want %v", m.Addr, waits, wantWait)
		}
	}
	lookup(a, 0)
	lookup(b, 0)
	// Both caps are spent: wait for a, whose slot frees first, then b.
	lookup(a, ms)
	lookup(b, ms)
	lookup(a, 2*ms)
	if st := p.Stats(); st[0].Throttled != 3 || st[1].Throttled != 3 {
		t.Fatalf("throttled = %d, %d, want 3, 3", st[0].Throttled, st[1].Throttled)
	}

	// Once the clock passes b's slots it has room again and is preferred
	// over a, which is still booked ahead.
	now = now.Add(2 * ms)
	lookup(b, 0)
	if st := p.Stats(); st[0].Throttled != 4 || st[1].Throttled != 3 {
		t.Fatalf("throttled = %d, %d, want 4, 3", st[0].Throttled, st[1].Throttled)
	}

	// A lookup of several record types books one slot per query.
	now = now.Add(time.Minute)
	if err := p.reserve(context.Background(), a, 3); err != nil {
		t.Fatal(err)
	}
	if !a.free.Equal(now.Add(3 * ms)) {
		t.Fatalf("after a 3-query lookup a is free at %v, want %v", a.free, now.Add(3*ms))
	}

	// A second opinion waits for a capped member rather than going without.
	if got := p.pickHealthy(b); got != a {
		t.Fatalf("pickHealthy(b) with a capped = %v, want a", got)
	}

	// Uncapped, nothing waits or is throttled.
	p.SetRatePerResolver(0)
	waits = nil
	if p.pick(nil) == nil || p.reserve(context.Background(), a, 1) != nil || len(waits) != 0 {
		t.Fatalf("uncapped pool waited: %v", waits)
	}
}

func TestPoolPickPrefersAvoidedHealthyOverBenched(t *testing.T) {
	p := NewPool([]string{"192.0.2.1:53", "192.0.2.2:53"}, time.Second)
	now := time.Unix(0, 0)
	p.now = func() time.Time { return now }
	healthy, benched := p.members[0], p.members[1]
	benched.until = now.Add(30 * time.Second)

	for i := 0; i < 4; i++ {
		if got := p.pick(healthy); got != healthy {
			t.Fatalf("pick(healthy) = %s, want the healthy avoided member over the benched one", got.Addr)
		}
	}
	// With every member benched, the one whose bench ends soonest is used.
	healthy.until = now.Add(time.Minute)
	if got := p.pick(healthy); got != benched {
		t.Fatalf("all benched: pick = %s, want the soonest-unbenched member", got.Addr)
	}
}
