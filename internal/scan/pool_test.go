package scan

import (
	"context"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// slowServer answers every query NXDOMAIN after delay. The test server's read
// loop handles one query at a time, like a resolver at its rate limit, so one
// such server caps throughput and twenty spread the load.
func slowServer(t *testing.T, delay time.Duration) string {
	addr, stop := startUDPDNSAction(t, func(string) dnsAction {
		time.Sleep(delay)
		return dnsAction{}
	})
	t.Cleanup(stop)
	return addr
}

func runPool(t *testing.T, cfg Config) (*Event, []Event) {
	t.Helper()
	events := make(chan Event, 256)
	go Run(context.Background(), cfg, events)
	done, errs, _ := collect(events)
	if done == nil {
		t.Fatalf("no EventDone; errors %v", errs)
	}
	return done, errs
}

// TestPoolSpreadsLoad is #69's load-spreading check without a wall-clock
// assertion (#167): every member of a 20-resolver pool takes part, and none
// carries more than its share. BenchmarkPoolSpreadsLoad keeps the timing view.
func TestPoolSpreadsLoad(t *testing.T) {
	trusted := slowServer(t, 0)
	var many []string
	for i := 0; i < 20; i++ {
		many = append(many, slowServer(t, 0))
	}
	pool := dns.NewPool(many, 5*time.Second)
	cfg := Config{
		Domain: "example.com", Entries: makeEntries(60), Concurrency: 20,
		Timeout: 5 * time.Second, Attempts: 3, Types: []string{"A"},
		Resolver: dns.NewResolver(5*time.Second, trusted), DNSServer: trusted,
		Pool: pool,
	}
	done, errs := runPool(t, cfg)
	if len(errs) != 0 || done.Processed != 60 {
		t.Fatalf("errs=%v processed=%d", errs, done.Processed)
	}
	stats := pool.Stats()
	var total int64
	for _, s := range stats {
		total += s.Lookups
	}
	for _, s := range stats {
		if s.Lookups == 0 {
			t.Errorf("resolver %s got no lookups; the pool did not spread the load: %+v", s.Addr, stats)
		}
		if s.Lookups*4 > total {
			t.Errorf("resolver %s got %d of %d lookups; want at most a quarter", s.Addr, s.Lookups, total)
		}
	}
}

// TestPoolRatePerResolver: with a per-resolver cap (#196) a scan still
// completes, and takes at least as long as the busiest member's queries need
// at the cap. Only that lower bound is checked; there is no upper bound on
// wall-clock time (#207).
func TestPoolRatePerResolver(t *testing.T) {
	trusted := slowServer(t, 0)
	pool := dns.NewPool([]string{slowServer(t, 0), slowServer(t, 0)}, 5*time.Second)
	const perSecond = 40
	pool.SetRatePerResolver(perSecond)
	cfg := Config{
		Domain: "example.com", Entries: makeEntries(20), Concurrency: 8,
		Timeout: 5 * time.Second, Attempts: 1, Types: []string{"A"},
		Resolver: dns.NewResolver(5*time.Second, trusted), DNSServer: trusted,
		Pool: pool,
	}
	start := time.Now()
	done, errs := runPool(t, cfg)
	elapsed := time.Since(start)
	if len(errs) != 0 || done.Processed != 20 {
		t.Fatalf("errs=%v processed=%d", errs, done.Processed)
	}
	var busiest, total int64
	for _, s := range pool.Stats() {
		busiest = max(busiest, s.Lookups)
		total += s.Lookups
	}
	if total < 20 {
		t.Fatalf("pool answered %d lookups, want at least 20: %+v", total, pool.Stats())
	}
	if floor := time.Duration(busiest-1) * time.Second / perSecond; elapsed < floor {
		t.Fatalf("scan took %v, under the %v its busiest member's %d lookups need at %d/s", elapsed, floor, busiest, perSecond)
	}
}

// BenchmarkPoolSpreadsLoad compares a scan over one slow resolver with the
// same scan over twenty; run with -bench to see the speedup.
func BenchmarkPoolSpreadsLoad(b *testing.B) {
	for _, size := range []int{1, 20} {
		b.Run(map[int]string{1: "one", 20: "twenty"}[size], func(b *testing.B) {
			trusted, stopT := startUDPDNSAction(b, func(string) dnsAction { return dnsAction{} })
			defer stopT()
			var pool []string
			for i := 0; i < size; i++ {
				addr, stop := startUDPDNSAction(b, func(string) dnsAction {
					time.Sleep(15 * time.Millisecond)
					return dnsAction{}
				})
				defer stop()
				pool = append(pool, addr)
			}
			for i := 0; i < b.N; i++ {
				cfg := Config{
					Domain: "example.com", Entries: makeEntries(60), Concurrency: 20,
					Timeout: 2 * time.Second, Attempts: 1, Types: []string{"A"},
					Resolver: dns.NewResolver(2*time.Second, trusted), DNSServer: trusted,
					Pool: dns.NewPool(pool, 2*time.Second),
				}
				events := make(chan Event, 256)
				go Run(context.Background(), cfg, events)
				for range events {
				}
			}
		})
	}
}

// TestPoolHitsAreRevalidated: a pool resolver that lies cannot inject a
// result, and reported records come from the trusted resolver.
func TestPoolHitsAreRevalidated(t *testing.T) {
	trustedAddr, stopT := startUDPDNSAction(t, func(name string) dnsAction {
		if name == "www.example.com" {
			return dnsAction{ip: [4]byte{192, 0, 2, 10}, hit: true}
		}
		return dnsAction{}
	})
	defer stopT()
	liar, stopL := startUDPDNSAction(t, func(name string) dnsAction {
		if name == "www.example.com" || name == "fake.example.com" {
			return dnsAction{ip: [4]byte{203, 0, 113, 66}, hit: true}
		}
		return dnsAction{}
	})
	defer stopL()

	cfg := Config{
		Domain: "example.com", Entries: []string{"www", "fake", "mail"}, Concurrency: 2,
		Timeout: time.Second, Attempts: 1, Types: []string{"A"},
		Resolver: dns.NewResolver(time.Second, trustedAddr), DNSServer: trustedAddr,
		Pool: dns.NewPool([]string{liar}, time.Second),
	}
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	var results []Event
	var done *Event
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			results = append(results, ev)
		case EventDone:
			e := ev
			done = &e
		}
	}
	if len(results) != 1 || results[0].Result.Subdomain != "www.example.com" {
		t.Fatalf("results = %+v, want only www", results)
	}
	if got := results[0].Result.Records; len(got) != 1 || got[0].Value != "192.0.2.10" {
		t.Fatalf("records = %v, want the trusted answer 192.0.2.10", got)
	}
	if s := done.Stats; s.PoolHits != 2 || s.Confirmed != 1 || s.Unconfirmed != 1 {
		t.Fatalf("pool stats = %+v, want 2 hits, 1 confirmed, 1 unconfirmed", s)
	}
}

// TestPoolBenchesDeadResolver: a resolver that never answers is benched and
// retries go elsewhere, so the scan completes without failures piling up.
func TestPoolBenchesDeadResolver(t *testing.T) {
	trusted := slowServer(t, 0)
	healthy := slowServer(t, 0)
	dead, stopD := startUDPDNSAction(t, func(string) dnsAction { return dnsAction{drop: true} })
	defer stopD()

	// The timeout covers the trusted preflight and every pool lookup. 50ms
	// made the test flaky (#253): a busy loopback server missed it, failing
	// the preflight or turning a healthy answer into a timeout. 250ms still
	// benches the dead member quickly, since it never answers.
	pool := dns.NewPool([]string{dead, healthy}, 250*time.Millisecond)
	cfg := Config{
		Domain: "example.com", Entries: makeEntries(80), Concurrency: 4,
		Timeout: 250 * time.Millisecond, Attempts: 2, Types: []string{"A"},
		Resolver: dns.NewResolver(time.Second, trusted), DNSServer: trusted, Pool: pool,
	}
	done, errs := runPool(t, cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if done.Stats.NXDomain != 80 {
		t.Fatalf("stats = %+v, want every name answered via the healthy resolver", done.Stats)
	}
	var deadStats dns.ResolverStats
	for _, s := range pool.Stats() {
		if s.Addr == dead {
			deadStats = s
		}
	}
	if deadStats.Benched == 0 {
		t.Fatalf("dead resolver never benched: %+v", deadStats)
	}
	if deadStats.Lookups > 40 {
		t.Errorf("dead resolver got %d lookups; benching should have stopped that", deadStats.Lookups)
	}
}

// TestPoolLyingNXDomainMember is #105's done-when: a pool member that
// answers NXDOMAIN to everything hides no real name, and is flagged. With an
// apex that resolves, canary checks catch it; without one, every untrusted
// NXDOMAIN gets a second opinion from the honest member.
func TestPoolLyingNXDomainMember(t *testing.T) {
	for _, apex := range []bool{true, false} {
		t.Run(map[bool]string{true: "canary", false: "second-opinion"}[apex], func(t *testing.T) {
			exists := func(name string) bool {
				return (apex && name == "example.com") || name == "p3.example.com" || name == "p17.example.com" || name == "p31.example.com"
			}
			honestHandler := func(name string) dnsAction {
				return dnsAction{ip: [4]byte{192, 0, 2, 10}, hit: exists(name)}
			}
			trusted, stopT := startUDPDNSAction(t, honestHandler)
			defer stopT()
			honest, stopH := startUDPDNSAction(t, honestHandler)
			defer stopH()
			liar, stopL := startUDPDNSAction(t, func(string) dnsAction { return dnsAction{} })
			defer stopL()

			pool := dns.NewPool([]string{liar, honest}, time.Second)
			cfg := Config{
				Domain: "example.com", Entries: makeEntries(40), Concurrency: 4,
				Timeout: time.Second, Attempts: 3, Types: []string{"A"},
				Resolver: dns.NewResolver(time.Second, trusted), DNSServer: trusted, Pool: pool,
			}
			events := make(chan Event, 256)
			go Run(context.Background(), cfg, events)
			found := map[string]bool{}
			for ev := range events {
				if ev.Kind == EventResult {
					found[ev.Result.Subdomain] = true
				}
			}
			for _, want := range []string{"p3.example.com", "p17.example.com", "p31.example.com"} {
				if !found[want] {
					t.Errorf("%s was hidden by the lying member; found %v", want, found)
				}
			}
			var liarStats dns.ResolverStats
			for _, s := range pool.Stats() {
				if s.Addr == liar {
					liarStats = s
				}
			}
			if liarStats.Contradicted == 0 {
				t.Errorf("the lying member was never contradicted: %+v", liarStats)
			}
			if apex && !liarStats.Flagged {
				t.Errorf("the lying member was not flagged: %+v", liarStats)
			}
		})
	}
}
