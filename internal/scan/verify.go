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
	limiter := dns.NewRateLimiter(cfg.Rate)
	live := !cfg.Simulate && cfg.resolveHook == nil
	if live {
		ctx = dns.WithLimiter(ctx, limiter)
	}
	var sent atomic.Int64
	ctx = dns.WithQueryCounter(ctx, &sent)
	attempts := max(cfg.Attempts, 1)
	sc := newScope(cfg.Exclude)

	lookup := func(name string) dns.Outcome {
		switch {
		case cfg.resolveHook != nil:
			if limiter.Wait(ctx) != nil {
				return dns.OutcomeCanceled
			}
			_, outcome := cfg.resolveHook(ctx, name)
			return outcome
		case cfg.Simulate:
			if limiter.Wait(ctx) != nil {
				return dns.OutcomeCanceled
			}
			if _, ok := dns.SimulateResolve(name, cfg.HitRate, cfg.Seed, nil, cfg.Types); ok {
				return dns.OutcomeFound
			}
			return dns.OutcomeNXDomain
		default:
			_, outcome := dns.ResolveDomainWithRetry(ctx, cfg.Resolver, name, cfg.Timeout, nil, attempts, cfg.Types)
			return outcome
		}
	}

	out := make(map[string]dns.Outcome, len(names))
	var mu sync.Mutex
	work := make(chan string)
	var wg sync.WaitGroup
	for range max(min(cfg.Concurrency, len(names)), 1) {
		wg.Go(func() {
			for name := range work {
				outcome := lookup(name)
				if outcome != dns.OutcomeFound && ctx.Err() != nil {
					outcome = dns.OutcomeCanceled
				}
				mu.Lock()
				out[name] = outcome
				mu.Unlock()
			}
		})
	}
feed:
	for _, name := range names {
		if sc.excluded(name) {
			continue
		}
		select {
		case work <- name:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	return out, sent.Load()
}
