package scan

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// The edge branches of the retry pass, the pool fallback and cancellation
// during preflight probes (#256).

// TestRetryWildcardAnswerIsFiltered: a name that timed out in the main pass
// and then gets the wildcard's answer on retry is filtered, not reported,
// and counted as recovered.
func TestRetryWildcardAnswerIsFiltered(t *testing.T) {
	const wildcardIP = "192.0.2.66"
	// The real server answers every name, so the probes learn the wildcard.
	server, stop := startUDPDNSAction(t, func(string) dnsAction {
		return dnsAction{ip: [4]byte{192, 0, 2, 66}, hit: true}
	})
	defer stop()
	var xCalls atomic.Int32
	cfg := Config{
		Domain: "example.com", Entries: []string{"x", "y"}, Concurrency: 1,
		Timeout: time.Second, Attempts: 1, Types: []string{"A"}, Force: true, RetryInconclusive: true,
		DNSServer: server, Resolver: dns.NewResolver(time.Second, server),
		// Candidates go through the hook: x times out once, then answers
		// like the wildcard; y answers like the wildcard straight away.
		resolveHook: func(_ context.Context, name string) ([]dns.Record, dns.Outcome) {
			if name == "x.example.com" && xCalls.Add(1) == 1 {
				return nil, dns.OutcomeTimeout
			}
			return []dns.Record{{Type: "A", Value: wildcardIP}}, dns.OutcomeFound
		},
	}
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	done, errs, results := collect(events)
	if len(errs) != 0 || done == nil {
		t.Fatalf("errors %v, done %v", errs, done)
	}
	st := done.Stats
	if results != 0 {
		t.Errorf("%d results; wildcard answers, retried or not, must be filtered", results)
	}
	if st.Retried != 1 || st.Recovered != 1 || st.WildcardFiltered != 2 || st.Timeout != 0 {
		t.Errorf("retried %d recovered %d wildcard_filtered %d timeout %d; want 1 1 2 0",
			st.Retried, st.Recovered, st.WildcardFiltered, st.Timeout)
	}
}

// TestRetryCancelledKeepsNamesPending: an interrupt during the retry pass
// leaves every name it did not settle inconclusive, with its first outcome,
// so a resumed run tests it again.
func TestRetryCancelledKeepsNamesPending(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls sync.Map
	cfg := Config{
		Domain: "example.com", Entries: []string{"a", "b", "c", "d"}, Concurrency: 1,
		Timeout: time.Second, Simulate: true, Attempts: 1, RetryInconclusive: true,
		resolveHook: func(ctx context.Context, name string) ([]dns.Record, dns.Outcome) {
			n, _ := calls.LoadOrStore(name, new(atomic.Int32))
			if n.(*atomic.Int32).Add(1) == 2 {
				cancel() // the interrupt arrives with the first retry
				<-ctx.Done()
			}
			return nil, dns.OutcomeTimeout
		},
	}
	events := make(chan Event, 64)
	go Run(ctx, cfg, events)
	done, errs, _ := collect(events)
	if len(errs) != 0 || done == nil {
		t.Fatalf("errors %v, done %v", errs, done)
	}
	st := done.Stats
	if st.Timeout != 4 || st.Retried != 0 || st.Recovered != 0 || len(st.Inconclusive) != 4 {
		t.Errorf("timeout %d retried %d recovered %d inconclusive %v; want 4 0 0 and all four names",
			st.Timeout, st.Retried, st.Recovered, st.Inconclusive)
	}
}

// TestPoolOfLiarsFallsBackToTrusted: once every pool member is flagged for
// injecting names, lookups go to the trusted resolver, and no injected name
// is ever reported.
func TestPoolOfLiarsFallsBackToTrusted(t *testing.T) {
	trusted, stopT := startUDPDNSAction(t, func(name string) dnsAction {
		if name == "example.com" || strings.HasPrefix(name, "www.") {
			return dnsAction{ip: [4]byte{192, 0, 2, 10}, hit: true}
		}
		return dnsAction{}
	})
	defer stopT()
	liar, stopL := startUDPDNSAction(t, func(string) dnsAction { // answers every name
		return dnsAction{ip: [4]byte{192, 0, 2, 66}, hit: true}
	})
	defer stopL()

	pool := dns.NewPool([]string{liar}, time.Second)
	entries := append([]string{"www"}, makeEntries(20)...)
	cfg := Config{
		Domain: "example.com", Entries: entries, Concurrency: 1,
		Timeout: time.Second, Attempts: 1, Types: []string{"A"},
		Resolver: dns.NewResolver(time.Second, trusted), DNSServer: trusted, Pool: pool,
	}
	done, errs := runPool(t, cfg)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	st := done.Stats
	if st.Found != 1 || st.NXDomain != int64(len(entries)-1) {
		t.Errorf("found %d nxdomain %d; want only www, and the trusted resolver's NXDOMAIN for the rest", st.Found, st.NXDomain)
	}
	if !pool.Stats()[0].Flagged {
		t.Errorf("the lying member was never flagged: %+v", pool.Stats()[0])
	}
	// Each injection before the flag costs a confirmation; after it the pool
	// has no member left and every lookup goes to the trusted resolver.
	if st.Unconfirmed == 0 || st.Unconfirmed >= int64(len(entries)-1) {
		t.Errorf("unconfirmed %d: want a few injections caught, then the trusted fallback for the rest", st.Unconfirmed)
	}
}

// TestCancelDuringWildcardProbes: an interrupt while the wildcard probes
// wait on a silent resolver ends the run with one done event and no error.
func TestCancelDuringWildcardProbes(t *testing.T) {
	silent, stop := startUDPDNSAction(t, func(string) dnsAction { return dnsAction{drop: true} })
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := Config{
		Domain: "example.com", Entries: []string{"www"}, Concurrency: 1,
		Timeout: 5 * time.Second, Attempts: 1, Types: []string{"A"},
		DNSServer: silent, Resolver: dns.NewResolver(5*time.Second, silent),
		// The preflight passes through the hook; the probes reach the server.
		resolveHook: func(context.Context, string) ([]dns.Record, dns.Outcome) { return nil, dns.OutcomeNXDomain },
	}
	events := make(chan Event, 64)
	go Run(ctx, cfg, events)
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	var dones, errs int
	for ev := range events {
		switch ev.Kind {
		case EventDone:
			dones++
		case EventError:
			errs++
			t.Errorf("unexpected error: %s", ev.Message)
		}
	}
	if dones != 1 || errs != 0 {
		t.Errorf("%d done events and %d errors, want exactly one done and none", dones, errs)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("the run took %v to end after the cancel", time.Since(start))
	}
}
