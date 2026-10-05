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

// TestPoolSpreadsLoad is #69's "measurably faster" check: the same scan over
// 20 slow resolvers finishes far sooner than over one.
func TestPoolSpreadsLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive")
	}
	trusted := slowServer(t, 0)
	var many []string
	for i := 0; i < 20; i++ {
		many = append(many, slowServer(t, 15*time.Millisecond))
	}
	scan := func(pool []string) time.Duration {
		cfg := Config{
			Domain: "example.com", Entries: makeEntries(60), Concurrency: 20,
			Timeout: 2 * time.Second, Attempts: 1, Types: []string{"A"},
			Resolver: dns.NewResolver(2*time.Second, trusted), DNSServer: trusted,
			Pool: dns.NewPool(pool, 2*time.Second),
		}
		start := time.Now()
		done, errs := runPool(t, cfg)
		if len(errs) != 0 || done.Processed != 60 {
			t.Fatalf("errs=%v processed=%d", errs, done.Processed)
		}
		return time.Since(start)
	}
	one := scan(many[:1])
	twenty := scan(many)
	t.Logf("1 resolver: %s, 20 resolvers: %s", one, twenty)
	if twenty*3 > one {
		t.Fatalf("20 resolvers took %s, 1 took %s; want at least 3x faster", twenty, one)
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
	if len(results) != 1 || results[0].Domain != "www.example.com" {
		t.Fatalf("results = %+v, want only www", results)
	}
	if got := results[0].Records; len(got) != 1 || got[0].Value != "192.0.2.10" {
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

	pool := dns.NewPool([]string{dead, healthy}, 50*time.Millisecond)
	cfg := Config{
		Domain: "example.com", Entries: makeEntries(80), Concurrency: 4,
		Timeout: 50 * time.Millisecond, Attempts: 2, Types: []string{"A"},
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
