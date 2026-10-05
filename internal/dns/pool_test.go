package dns

import (
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
