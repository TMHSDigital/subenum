package scan

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// Verify looks each name up once more and returns its outcome, with the
// number of DNS queries sent. -diff uses it to confirm that a name from a
// previous run is really gone before reporting it removed (#110): a name may
// be missing from this run only because it was not a candidate (a smaller
// wordlist, no -recursive or -permute) or because its lookup failed.
//
// Lookups use the trusted resolver (never Pool) or the simulation, and honour
// Concurrency, Rate, Attempts, Timeout and Types. Names in Exclude are not
// looked up and are absent from the result. Wildcard answers are not
// filtered: a name under a wildcard still resolves, so it is never reported
// removed. Cancelled lookups report OutcomeCanceled.
func Verify(ctx context.Context, cfg Config, names []string) (map[string]dns.Outcome, int64) {
	if cfg.Resolver == nil {
		cfg.Resolver = dns.NewResolver(cfg.Timeout, cfg.DNSServer)
	}
	defer dns.CloseIdleConnections(cfg.Resolver)
	cfg.Attempts = max(cfg.Attempts, 1)
	// Live lookups carry the limiter on ctx and take a slot per DNS query;
	// simulated and hooked lookups take one slot per name, as in Run.
	limiter := dns.NewRateLimiter(cfg.Rate)
	var nameLimiter *dns.RateLimiter
	if cfg.Simulate || cfg.resolveHook != nil {
		nameLimiter = limiter
	} else {
		ctx = dns.WithLimiter(ctx, limiter)
	}
	var sent atomic.Int64
	ctx = dns.WithQueryCounter(ctx, &sent)
	sc := newScope(cfg.Exclude)

	lookup := func(name string) dns.Outcome {
		if nameLimiter.Wait(ctx) != nil {
			return dns.OutcomeCanceled
		}
		_, outcome := cfg.resolve(ctx, name, nil)
		return outcome
	}

	out := make(map[string]dns.Outcome, len(names))
	var mu sync.Mutex
	work := make(chan string)
	var wg sync.WaitGroup
	for range max(min(cfg.Concurrency, len(names)), 1) {
		wg.Go(func() {
			for name := range work {
				outcome := settle(ctx, lookup(name))
				mu.Lock()
				out[name] = outcome
				mu.Unlock()
			}
		})
	}
	var undispatched []string
	for i, name := range names {
		if sc.excluded(name) {
			continue
		}
		select {
		case work <- name:
			continue
		case <-ctx.Done():
		}
		undispatched = names[i:]
		break
	}
	close(work)
	wg.Wait()
	// Names never handed to a worker were cancelled too; without an entry a
	// caller would read the zero value, OutcomeFound (#151).
	for _, name := range undispatched {
		if !sc.excluded(name) {
			out[name] = dns.OutcomeCanceled
		}
	}
	return out, sent.Load()
}
