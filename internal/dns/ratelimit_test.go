package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNewRateLimiterUnlimited(t *testing.T) {
	if l := NewRateLimiter(0); l != nil {
		t.Fatalf("NewRateLimiter(0) = %v, want nil", l)
	}
	var l *RateLimiter
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("nil limiter Wait: %v", err)
	}
}

// TestRateLimiterNoUnderDelivery covers ROADMAP N1: under contention a ticker
// dropped ticks and delivered below -rate. Reservations must keep pace.
func TestRateLimiterNoUnderDelivery(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive")
	}
	const rate, n = 100, 50
	l := NewRateLimiter(rate)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < n/16+1; j++ {
				_ = l.Wait(context.Background())
				time.Sleep(5 * time.Millisecond) // simulate a busy worker
			}
		}()
	}
	wg.Wait()
	calls := 16 * (n/16 + 1)
	ideal := time.Duration(calls-1) * time.Second / rate
	elapsed := time.Since(start)
	if elapsed < ideal*8/10 {
		t.Errorf("finished in %s, faster than the rate allows (ideal %s)", elapsed, ideal)
	}
	if elapsed > ideal*15/10+100*time.Millisecond {
		t.Errorf("finished in %s, well below the configured rate (ideal %s)", elapsed, ideal)
	}
}

func TestRateLimiterCancel(t *testing.T) {
	l := NewRateLimiter(1)
	_ = l.Wait(context.Background()) // consume the immediate slot
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx); err == nil {
		t.Fatal("Wait on a cancelled context returned nil")
	}
}

// TestResolverPacesWireQueries covers #32: -rate must bound DNS messages on the
// wire, not candidate names. Each name below costs two queries (A and AAAA),
// so a per-name limiter would finish in half the time this test requires. The
// 500ms per-type timeout is far shorter than the ~2s total wait, proving time
// spent queued for a slot does not count against the lookup timeout.
func TestResolverPacesWireQueries(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive")
	}
	srv := startTestDNS(t, map[string]testReply{"*": {A: "192.0.2.7"}})
	const rate, names = 10, 10
	r := NewResolver(2*time.Second, srv.addr)
	ctx := WithLimiter(context.Background(), NewRateLimiter(rate))

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < names; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			recs, _, err := ResolveTypes(ctx, r, "h"+string(rune('a'+i))+".example.com", 500*time.Millisecond, DefaultTypes)
			if len(recs) == 0 {
				t.Errorf("lookup %d: no records (err %v)", i, err)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	q := srv.Queries()
	if q < 2*names {
		t.Fatalf("server saw %d queries, want at least %d (A+AAAA per name)", q, 2*names)
	}
	minExpected := time.Duration(q-1) * time.Second / rate * 8 / 10
	if elapsed < minExpected {
		t.Errorf("%d wire queries in %s: faster than -rate %d allows (min %s)", q, elapsed, rate, minExpected)
	}
}

// TestRateChargesEveryWireQuery covers #50: the slots charged for a lookup
// equal the DNS queries the server receives, for every record type and when
// Go's resolver retries a SERVFAIL internally.
func TestRateChargesEveryWireQuery(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"ok.example.com":    {A: "192.0.2.1", AAAA: "2001:db8::1"},
		"alias.example.com": {CNAME: "ok.example.com"},
		"bad.example.com":   {ServFailA: true},
	})
	for _, tc := range []struct{ name, typ string }{
		{"ok.example.com", "A"},
		{"ok.example.com", "AAAA"},
		{"alias.example.com", "CNAME"},
		{"ok.example.com", "CNAME"},
		{"bad.example.com", "A"},
	} {
		t.Run(tc.typ+" "+tc.name, func(t *testing.T) {
			lim := NewRateLimiter(1_000_000)
			ctx := WithLimiter(context.Background(), lim)
			before := srv.Queries()
			_, _, _ = ResolveTypes(ctx, srv.Resolver(time.Second), tc.name, time.Second, []string{tc.typ})
			wire := srv.Queries() - before
			lim.mu.Lock()
			charged := lim.reserved
			lim.mu.Unlock()
			t.Logf("wire queries %d, charged %d", wire, charged)
			if wire != charged {
				t.Fatalf("wire queries = %d, charged slots = %d; want equal", wire, charged)
			}
		})
	}
}

// TestRefusedIsClassifiedRefused covers the second half of #50: RCODE REFUSED
// counts as refused (Go reports it as "server misbehaving"), and the error
// names the configured server.
func TestRefusedIsClassifiedRefused(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{"*": {Refused: true}})
	_, _, err := ResolveTypes(context.Background(), srv.Resolver(time.Second), "x.example.com", time.Second, []string{"A"})
	if got := Classify(err); got != OutcomeRefused {
		t.Fatalf("Classify(%v) = %v, want refused", err, got)
	}
	var de *net.DNSError
	if !errors.As(err, &de) || de.Server != srv.addr {
		t.Fatalf("error server = %q, want %q", de.Server, srv.addr)
	}
}
