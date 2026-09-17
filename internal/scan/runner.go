package scan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

const (
	reliabilityMinJobs     = 200
	reliabilityFailPercent = 20
	queueCompactEvery      = 1024
	recursionRefuseCeiling = 1e7
)

// Config holds all parameters needed to run a subdomain scan.
type Config struct {
	Domain      string
	Entries     []string
	Concurrency int
	Timeout     time.Duration
	DNSServer   string
	Simulate    bool
	HitRate     int
	Attempts    int
	Force       bool
	Verbose     bool
	Rate        int           // max DNS queries per second across all workers (0 = unlimited)
	Types       []string      // record types to look up (A, AAAA, CNAME); empty = A,AAAA
	Recursive   bool          // enumerate subdomains of discovered subdomains
	Depth       int           // max recursion depth (1 = no recursion)
	NoAbort     bool          // keep scanning after the reliability guard fires
	MaxQueries  int           // cap on admitted jobs (0 = unlimited)
	Resolver    *net.Resolver // reused across lookups; nil means scan.Run constructs one

	// resolveHook, if set, replaces SimulateResolve / ResolveDomainWithRetry.
	// Tests inject classified outcomes through this field without network I/O.
	resolveHook func(ctx context.Context, domain string) ([]dns.Record, dns.Outcome)
}

// Stats is a snapshot of per-outcome query counters. Populated on EventDone.
type Stats struct {
	Found            int64
	NXDomain         int64
	Timeout          int64
	Refused          int64
	Other            int64
	WildcardFiltered int64
}

// Sum returns the number of classified queries (found + negatives + failures +
// wildcard-filtered).
func (s Stats) Sum() int64 {
	return s.Found + s.NXDomain + s.Timeout + s.Refused + s.Other + s.WildcardFiltered
}

func (s Stats) failures() int64 {
	return s.Timeout + s.Refused + s.Other
}

type counters struct {
	found            atomic.Int64
	nxdomain         atomic.Int64
	timeout          atomic.Int64
	refused          atomic.Int64
	other            atomic.Int64
	wildcardFiltered atomic.Int64
}

func (c *counters) add(o dns.Outcome) {
	switch o {
	case dns.OutcomeFound:
		c.found.Add(1)
	case dns.OutcomeNXDomain:
		c.nxdomain.Add(1)
	case dns.OutcomeTimeout:
		c.timeout.Add(1)
	case dns.OutcomeRefused:
		c.refused.Add(1)
	case dns.OutcomeOther:
		c.other.Add(1)
	default:
		c.other.Add(1)
	}
}

func (c *counters) snapshot() Stats {
	return Stats{
		Found:            c.found.Load(),
		NXDomain:         c.nxdomain.Load(),
		Timeout:          c.timeout.Load(),
		Refused:          c.refused.Load(),
		Other:            c.other.Load(),
		WildcardFiltered: c.wildcardFiltered.Load(),
	}
}

type wildcardCache struct {
	mu    sync.Mutex
	known map[string]bool
}

func (c *wildcardCache) isWildcard(ctx context.Context, cfg Config, parent string) (bool, error) {
	c.mu.Lock()
	if v, ok := c.known[parent]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	is, _, err := dns.CheckWildcard(ctx, cfg.Resolver, parent, cfg.Timeout)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	if c.known == nil {
		c.known = make(map[string]bool)
	}
	c.known[parent] = is
	c.mu.Unlock()
	return is, nil
}

func recordsSubset(got, fp []dns.Record) bool {
	if len(fp) == 0 || len(got) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(fp))
	for _, r := range fp {
		set[r.Type+"\x00"+r.Value] = struct{}{}
	}
	for _, r := range got {
		if _, ok := set[r.Type+"\x00"+r.Value]; !ok {
			return false
		}
	}
	return true
}

// RecursionCeiling returns the theoretical job count for a recursive scan:
// sum over d=1..depth of n^d, as a float so large wordlists do not overflow.
func RecursionCeiling(n, depth int) float64 {
	if n <= 0 || depth <= 0 {
		return 0
	}
	var total, term float64
	term = float64(n)
	for d := 1; d <= depth; d++ {
		total += term
		term *= float64(n)
	}
	return total
}

// job is a single unit of work: a fully qualified domain to test and its depth
// in the recursion tree (initial entries are depth 1).
type job struct {
	domain string
	depth  int
}

// EventKind categorises a scan event.
type EventKind int

const (
	EventResult   EventKind = iota // a subdomain resolved
	EventProgress                  // progress update
	EventWildcard                  // wildcard DNS detected
	EventError                     // non-fatal error message
	EventDone                      // scan finished
)

// Event is emitted on the events channel during a scan.
type Event struct {
	Kind      EventKind
	Domain    string       // EventResult: the resolved subdomain
	Records   []dns.Record // EventResult: the resolved records (A/AAAA/CNAME)
	Processed int64        // EventProgress
	Total     int64        // EventProgress
	Found     int64        // EventProgress / EventDone
	Message   string       // EventError / EventWildcard
	Stats     Stats        // EventDone: per-outcome counters
}

// Run executes the subdomain scan, sending events to the provided channel.
// The caller must close or cancel ctx to abort early.
// Run closes events when the scan completes.
func Run(ctx context.Context, cfg Config, events chan<- Event) {
	defer close(events)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var total, processed, found int64
	var stats counters
	var guardOnce sync.Once
	atomic.StoreInt64(&total, int64(len(cfg.Entries)))

	maxDepth := cfg.Depth
	if maxDepth < 1 {
		maxDepth = 1
	}

	if cfg.Resolver == nil {
		cfg.Resolver = dns.NewResolver(cfg.Timeout, cfg.DNSServer)
	}

	if cfg.Recursive {
		ceiling := RecursionCeiling(len(cfg.Entries), maxDepth)
		if ceiling > recursionRefuseCeiling && cfg.MaxQueries == 0 && !cfg.Force {
			events <- Event{Kind: EventError, Message: fmt.Sprintf(
				"refusing to start: -recursive -depth %d with %d entries can generate up to %.1e queries; set -max-queries or -force",
				maxDepth, len(cfg.Entries), ceiling)}
			return
		}
		consider := "Consider -max-queries."
		if maxDepth > 1 {
			consider = fmt.Sprintf("Consider -depth %d or -max-queries.", maxDepth-1)
		}
		events <- Event{Kind: EventWildcard, Message: fmt.Sprintf(
			"Warning: -recursive -depth %d with %d entries can generate up to %.1e queries.\n%s",
			maxDepth, len(cfg.Entries), ceiling, consider)}
	}

	if !cfg.Simulate && cfg.resolveHook == nil {
		types := cfg.Types
		if len(types) == 0 {
			types = dns.DefaultTypes
		}
		records, _, err := dns.ResolveTypes(ctx, cfg.Resolver, cfg.Domain, cfg.Timeout, types)
		outcome := dns.Classify(err)
		if len(records) > 0 {
			outcome = dns.OutcomeFound
		}
		if outcome != dns.OutcomeFound && outcome != dns.OutcomeNXDomain {
			msg := fmt.Sprintf("resolver %s failed preflight for %s: %v", cfg.DNSServer, cfg.Domain, err)
			events <- Event{Kind: EventError, Message: msg}
			return
		}
	}

	var fingerprint []dns.Record
	wc := &wildcardCache{known: make(map[string]bool)}

	// Wildcard detection (skip in simulation mode).
	if !cfg.Simulate {
		isWildcard, fp, err := dns.CheckWildcard(ctx, cfg.Resolver, cfg.Domain, cfg.Timeout)
		if err != nil {
			events <- Event{Kind: EventError, Message: "wildcard detection failed: " + err.Error()}
			return
		}
		fingerprint = fp
		if isWildcard {
			msg := "WARNING: Wildcard DNS detected - all subdomains resolve for " + cfg.Domain
			events <- Event{Kind: EventWildcard, Message: msg}
			if !cfg.Force {
				events <- Event{Kind: EventError, Message: "Results would be meaningless. Use -force to scan anyway."}
				return
			}
		}
	}

	var wg sync.WaitGroup

	// Work queue channels. The dispatcher owns the lifecycle: it tracks
	// outstanding work and closes jobs only once every enqueued job has
	// completed. This lets workers safely enqueue depth-capped children after
	// the initial feed, which the old "close right after feeding" shape could
	// not do without risking a send on a closed channel.
	jobs := make(chan job)
	enqueue := make(chan job)
	completed := make(chan struct{})

	// Optional rate limiter: a shared ticker gate paces total queries per second
	// across the whole worker pool. nil means unlimited.
	var limiter <-chan time.Time
	if cfg.Rate > 0 {
		interval := time.Second / time.Duration(cfg.Rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		rl := time.NewTicker(interval)
		defer rl.Stop()
		limiter = rl.C
	}

	// Progress ticker - fires every second.
	// tickerDone signals the goroutine to stop; tickerStopped confirms it has
	// fully exited so we never close events while a send is pending.
	tickerDone := make(chan struct{})
	tickerStopped := make(chan struct{})
	ticker := time.NewTicker(time.Second)
	go func() {
		defer close(tickerStopped)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p := atomic.LoadInt64(&processed)
				f := atomic.LoadInt64(&found)
				select {
				case events <- Event{Kind: EventProgress, Processed: p, Total: atomic.LoadInt64(&total), Found: f}:
				case <-tickerDone:
					return
				case <-ctx.Done():
					return
				}
			case <-tickerDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Dispatcher: owns the queue, the visited set (loop/dup protection), and the
	// pending-work counter. It closes jobs when pending reaches zero (all work
	// done) or when the context is cancelled.
	go func() {
		visited := make(map[string]bool, len(cfg.Entries))
		queue := make([]job, 0, len(cfg.Entries))
		head := 0
		admitted := 0
		skipped := 0
		admit := func(j job) bool {
			if visited[j.domain] {
				return false
			}
			visited[j.domain] = true
			if cfg.MaxQueries > 0 && admitted >= cfg.MaxQueries {
				skipped++
				return false
			}
			queue = append(queue, j)
			admitted++
			return true
		}
		for _, entry := range cfg.Entries {
			_ = admit(job{domain: entry + "." + cfg.Domain, depth: 1})
		}
		pending := admitted
		atomic.StoreInt64(&total, int64(pending))
		closeJobs := func() {
			if skipped > 0 {
				select {
				case events <- Event{Kind: EventWildcard, Message: fmt.Sprintf(
					"query cap reached (-max-queries %d); skipped %d additional jobs", cfg.MaxQueries, skipped)}:
				case <-ctx.Done():
				}
			}
			close(jobs)
		}
		if pending == 0 {
			closeJobs()
			return
		}
		for {
			var out chan job
			var next job
			if head < len(queue) {
				out = jobs
				next = queue[head]
			}
			select {
			case <-ctx.Done():
				closeJobs()
				return
			case j := <-enqueue:
				if admit(j) {
					pending++
					atomic.AddInt64(&total, 1)
				}
			case out <- next:
				head++
				switch {
				case head == len(queue):
					queue = queue[:0]
					head = 0
				case head >= queueCompactEvery:
					queue = append([]job(nil), queue[head:]...)
					head = 0
				}
			case <-completed:
				pending--
				if pending == 0 {
					closeJobs()
					return
				}
			}
		}
	}()

	// Worker pool.
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				processJob(ctx, cfg, j, maxDepth, limiter, events, enqueue, &processed, &found, &stats, cancel, &guardOnce, fingerprint, wc)
				select {
				case completed <- struct{}{}:
				case <-ctx.Done():
				}
			}
		}()
	}

	wg.Wait()
	// Stop the ticker goroutine and wait for it to fully exit before emitting
	// EventDone, so the deferred close(events) can never race an in-flight
	// ticker send.
	close(tickerDone)
	<-tickerStopped

	snap := stats.snapshot()
	events <- Event{
		Kind:      EventDone,
		Processed: atomic.LoadInt64(&processed),
		Total:     atomic.LoadInt64(&total),
		Found:     atomic.LoadInt64(&found),
		Stats:     snap,
	}
}

// processJob resolves a single job and, on success, optionally enqueues
// depth-capped children for recursive enumeration.
func processJob(ctx context.Context, cfg Config, j job, maxDepth int, limiter <-chan time.Time, events chan<- Event, enqueue chan<- job, processed, found *int64, st *counters, cancel context.CancelFunc, guardOnce *sync.Once, fp []dns.Record, wc *wildcardCache) {
	if ctx.Err() != nil {
		return
	}
	if limiter != nil {
		select {
		case <-limiter:
		case <-ctx.Done():
			return
		}
	}

	var outcome dns.Outcome
	var records []dns.Record
	switch {
	case cfg.resolveHook != nil:
		records, outcome = cfg.resolveHook(ctx, j.domain)
	case cfg.Simulate:
		var ok bool
		records, ok = dns.SimulateResolve(j.domain, cfg.HitRate, cfg.Verbose, cfg.Types)
		if ok {
			outcome = dns.OutcomeFound
		} else {
			outcome = dns.OutcomeNXDomain
		}
	default:
		records, outcome = dns.ResolveDomainWithRetry(ctx, cfg.Resolver, j.domain, cfg.Timeout, cfg.Verbose, cfg.Attempts, cfg.Types)
	}

	if outcome == dns.OutcomeFound && recordsSubset(records, fp) {
		st.wildcardFiltered.Add(1)
		n := atomic.AddInt64(processed, 1)
		checkReliability(cfg, n, st, events, cancel, guardOnce)
		return
	}

	st.add(outcome)
	n := atomic.AddInt64(processed, 1)
	checkReliability(cfg, n, st, events, cancel, guardOnce)

	if outcome != dns.OutcomeFound {
		return
	}

	atomic.AddInt64(found, 1)
	events <- Event{Kind: EventResult, Domain: j.domain, Records: records}

	if cfg.Recursive && j.depth < maxDepth {
		if !cfg.Simulate && cfg.resolveHook == nil {
			isWild, err := wc.isWildcard(ctx, cfg, j.domain)
			if err != nil {
				events <- Event{Kind: EventWildcard, Message: "skipping recursive expansion of " + j.domain + ": wildcard check failed: " + err.Error()}
				return
			}
			if isWild {
				events <- Event{Kind: EventWildcard, Message: "wildcard DNS at " + j.domain + "; skipping recursive expansion"}
				return
			}
		}
		for _, entry := range cfg.Entries {
			child := job{domain: entry + "." + j.domain, depth: j.depth + 1}
			select {
			case enqueue <- child:
			case <-ctx.Done():
				return
			}
		}
	}
}

func checkReliability(cfg Config, processed int64, st *counters, events chan<- Event, cancel context.CancelFunc, once *sync.Once) {
	if processed < reliabilityMinJobs {
		return
	}
	snap := st.snapshot()
	failures := snap.failures()
	if failures*100 <= processed*int64(reliabilityFailPercent) {
		return
	}
	once.Do(func() {
		rate := float64(failures) * 100 / float64(processed)
		verb := "aborting scan"
		if cfg.NoAbort {
			verb = "warning"
		}
		msg := fmt.Sprintf("%s: %.0f%% of %d queries failed (timeout/refused/other); likely resolver rate-limiting at -t %d and -rate %d",
			verb, rate, processed, cfg.Concurrency, cfg.Rate)
		events <- Event{Kind: EventError, Message: msg}
		if !cfg.NoAbort {
			cancel()
		}
	})
}
