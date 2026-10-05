// Package scan runs a subdomain scan: it validates options, dispatches
// candidate names to a worker pool, filters wildcard answers and reports
// results and statistics as events.
package scan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

const (
	reliabilityMinJobs     = 200
	reliabilityFailPercent = 20
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
	Seed        uint64 // simulation seed: the same seed reproduces the same simulated results
	Attempts    int
	Force       bool
	Verbose     bool          // log every lookup; through Logf when set, else unsynchronized to stderr
	Logf        dns.Logf      // receives verbose lines when Verbose is set
	Rate        int           // max DNS messages per second on the wire, all workers combined (0 = unlimited)
	Types       []string      // record types to look up (A, AAAA, CNAME); empty = A,AAAA
	Recursive   bool          // enumerate subdomains of discovered subdomains
	Depth       int           // max recursion depth (1 = no recursion)
	NoAbort     bool          // keep scanning after the reliability guard fires
	MaxQueries  int           // cap on admitted candidate names (jobs), not wire queries (0 = unlimited)
	Resolver    *net.Resolver // reused across lookups; nil means scan.Run constructs one

	// resolveHook, if set, replaces SimulateResolve / ResolveDomainWithRetry.
	// Tests inject classified outcomes through this field without network I/O.
	resolveHook func(ctx context.Context, domain string) ([]dns.Record, dns.Outcome)
}

// logf returns the verbose logger for lookups, or nil when Verbose is off.
func (c Config) logf() dns.Logf {
	if !c.Verbose {
		return nil
	}
	if c.Logf != nil {
		return c.Logf
	}
	return dns.StderrLogf
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

	is, _, err := dns.CheckWildcard(ctx, cfg.Resolver, parent, cfg.Timeout, cfg.Types, cfg.Attempts)
	if err != nil {
		return false, err // never cache an inconclusive check
	}
	c.mu.Lock()
	if c.known == nil {
		c.known = make(map[string]bool)
	}
	c.known[parent] = is
	c.mu.Unlock()
	return is, nil
}

// fingerprint is the root wildcard's known answers. A result whose records
// all appear in it is a wildcard answer. Near-miss results grow it with fresh
// probes (see revalidate), so it is shared by the workers and locked.
type fingerprint struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

func newFingerprint(recs []dns.Record) *fingerprint {
	f := &fingerprint{set: make(map[string]struct{}, len(recs))}
	f.add(recs)
	return f
}

func recordKey(r dns.Record) string { return r.Type + "\x00" + r.Value }

func (f *fingerprint) add(recs []dns.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range recs {
		f.set[recordKey(r)] = struct{}{}
	}
}

// match reports whether every record of got is a known wildcard answer
// (covered) and whether at least one is (overlaps). An empty fingerprint or
// result never matches.
func (f *fingerprint) match(got []dns.Record) (covered, overlaps bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.set) == 0 || len(got) == 0 {
		return false, false
	}
	covered = true
	for _, r := range got {
		if _, ok := f.set[recordKey(r)]; ok {
			overlaps = true
		} else {
			covered = false
		}
	}
	return covered, overlaps
}

// nearMissProbes is how many fresh random labels re-validate a result that
// shares some but not all records with the wildcard fingerprint (#48).
const nearMissProbes = 2

// isWildcardAnswer reports whether records are a wildcard answer for name. A
// result that only partly matches the fingerprint is a near miss, typical of
// a wildcard served from a rotating pool: fresh random labels under the same
// parent are probed, their answers join the fingerprint, and the result is
// checked again. Results that share nothing with the fingerprint (real names)
// cost no extra queries.
func isWildcardAnswer(ctx context.Context, cfg Config, fp *fingerprint, name string, records []dns.Record) bool {
	covered, overlaps := fp.match(records)
	if covered || !overlaps || cfg.Simulate || cfg.resolveHook != nil {
		return covered
	}
	parent := name
	if i := strings.IndexByte(name, '.'); i >= 0 {
		parent = name[i+1:]
	}
	for i := 0; i < nearMissProbes; i++ {
		recs, _ := dns.ResolveDomainWithRetry(ctx, cfg.Resolver, dns.RandomLabel()+"."+parent, cfg.Timeout, nil, cfg.Attempts, cfg.Types)
		fp.add(recs)
		if covered, _ = fp.match(records); covered {
			return true
		}
	}
	return false
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

// workerCount caps the pool at the most jobs the scan can produce, so a huge
// -t on a short wordlist does not spawn millions of idle goroutines (#58).
func workerCount(cfg Config, maxDepth int) int {
	depth := 1
	if cfg.Recursive {
		depth = maxDepth
	}
	work := RecursionCeiling(len(cfg.Entries), depth)
	if cfg.MaxQueries > 0 {
		work = min(work, float64(cfg.MaxQueries))
	}
	return max(1, int(min(float64(cfg.Concurrency), work)))
}

// job is a single unit of work: a fully qualified domain to test and its depth
// in the recursion tree (initial entries are depth 1).
type job struct {
	domain string
	depth  int
}

// expansion is a pending run of candidates: every cfg.Entries[next:] prepended
// to parent, at the given depth. The root expansion has parent cfg.Domain.
type expansion struct {
	parent string
	depth  int
	next   int
}

// EventKind categorises a scan event.
type EventKind int

// Event kinds.
const (
	// EventResult reports a resolved subdomain.
	EventResult   EventKind = iota
	EventProgress           // progress update
	EventNotice             // informational notice; see Event.Notice
	EventError              // non-fatal error message
	EventDone               // scan finished
)

// NoticeKind says what an EventNotice is about, so consumers can style or
// filter notices without parsing the message (#68).
type NoticeKind int

// Notice kinds.
const (
	// NoticeWildcard means wildcard DNS was detected, or its check failed
	// under -force.
	NoticeWildcard NoticeKind = iota + 1
	NoticeCap                 // -max-queries reached; candidates skipped
	NoticeCeiling             // recursive scan may generate very many queries
	NoticeSkip                // a recursive branch was not expanded
)

// String names a notice kind for structured output.
func (k NoticeKind) String() string {
	switch k {
	case NoticeWildcard:
		return "wildcard"
	case NoticeCap:
		return "cap"
	case NoticeCeiling:
		return "ceiling"
	case NoticeSkip:
		return "skip"
	}
	return "notice"
}

// Event is emitted on the events channel during a scan.
type Event struct {
	Kind      EventKind
	Notice    NoticeKind   // EventNotice: what the notice is about
	Domain    string       // EventResult: the resolved subdomain
	Records   []dns.Record // EventResult: the resolved records (A/AAAA/CNAME)
	Processed int64        // EventProgress
	Total     int64        // EventProgress
	Found     int64        // EventProgress / EventDone
	Message   string       // EventError / EventNotice
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

	// One limiter paces the whole scan. Live lookups carry it on ctx and take a
	// slot per DNS query they send (every record type, every retry, wildcard
	// probes and the preflight), so -rate bounds wire queries, not names (#32).
	// Simulated and hooked lookups have no wire traffic and take one slot per job.
	limiter := dns.NewRateLimiter(cfg.Rate)
	if cfg.Resolver == nil {
		cfg.Resolver = dns.NewResolver(cfg.Timeout, cfg.DNSServer)
	}
	var jobLimiter *dns.RateLimiter
	if cfg.Simulate || cfg.resolveHook != nil {
		jobLimiter = limiter
	} else {
		ctx = dns.WithLimiter(ctx, limiter)
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
		events <- Event{Kind: EventNotice, Notice: NoticeCeiling, Message: fmt.Sprintf(
			"Warning: -recursive -depth %d with %d entries can generate up to %.1e queries.\n%s",
			maxDepth, len(cfg.Entries), ceiling, consider)}
	}

	if !cfg.Simulate && cfg.resolveHook == nil {
		// Retried like any other lookup, so one dropped packet cannot abort a
		// scan that -attempts would otherwise complete (#57).
		attempts := max(cfg.Attempts, 1)
		_, outcome := dns.ResolveDomainWithRetry(ctx, cfg.Resolver, cfg.Domain, cfg.Timeout, nil, attempts, cfg.Types)
		if ctx.Err() != nil {
			return // interrupted during preflight: not a resolver failure
		}
		if outcome != dns.OutcomeFound && outcome != dns.OutcomeNXDomain {
			msg := fmt.Sprintf("resolver %s failed preflight for %s: %s after %d attempt(s)", cfg.DNSServer, cfg.Domain, outcome, attempts)
			events <- Event{Kind: EventError, Message: msg}
			return
		}
	}

	fingerprint := newFingerprint(nil)
	wc := &wildcardCache{known: make(map[string]bool)}

	// Wildcard detection (skip in simulation mode).
	if !cfg.Simulate {
		isWildcard, fp, err := dns.FingerprintWildcard(ctx, cfg.Resolver, cfg.Domain, cfg.Timeout, cfg.Types, cfg.Attempts)
		if ctx.Err() != nil {
			return // interrupted during wildcard probes
		}
		// An inconclusive check is never "no wildcard": under a real wildcard
		// every candidate would resolve and flood the results (#47). -force
		// scans anyway, but without a fingerprint to filter with.
		if err != nil && !cfg.Force {
			events <- Event{Kind: EventError, Message: "wildcard detection failed: " + err.Error() + "; results could not be filtered. Use -force to scan anyway."}
			return
		}
		if err != nil {
			events <- Event{Kind: EventNotice, Notice: NoticeWildcard, Message: "WARNING: wildcard detection failed (" + err.Error() + "); scanning without wildcard filtering because of -force"}
		}
		fingerprint.add(fp)
		if isWildcard {
			msg := "WARNING: Wildcard DNS detected - all subdomains resolve for " + cfg.Domain
			events <- Event{Kind: EventNotice, Notice: NoticeWildcard, Message: msg}
			if !cfg.Force {
				events <- Event{Kind: EventError, Message: "Results would be meaningless. Use -force to scan anyway."}
				return
			}
		}
	}

	var wg sync.WaitGroup

	// Work queue channels. The dispatcher owns the lifecycle: it tracks
	// outstanding work and closes jobs only once every dispatched job has
	// completed. Workers send found parents on enqueue (before signalling
	// completed) and the dispatcher expands them into depth-capped children.
	jobs := make(chan job)
	enqueue := make(chan job)
	completed := make(chan struct{})

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

	// Dispatcher: owns the expansion queue, the visited set (loop/dup
	// protection), and the pending-work counter. It closes jobs when no
	// candidates remain and every dispatched job has completed, or when the
	// context is cancelled.
	//
	// Candidates are generated lazily. The queue holds expansions (a parent
	// plus a cursor into cfg.Entries) rather than one job per name, so depth-1
	// names are built only as they are dispatched and a found parent costs one
	// enqueue instead of len(Entries) (#49). Once -max-queries is reached the
	// remaining candidates are counted, never built or recorded (#51).
	go func() {
		n := len(cfg.Entries)
		visited := make(map[string]struct{}, n)
		frontier := []expansion{{parent: cfg.Domain, depth: 1}}
		head := 0
		remaining := n // candidates not yet generated
		admitted := 0
		skipped := 0
		capped := false
		pending := 0 // dispatched jobs not yet completed

		publishTotal := func() {
			t := admitted + remaining
			if cfg.MaxQueries > 0 && t > cfg.MaxQueries {
				t = cfg.MaxQueries
			}
			atomic.StoreInt64(&total, int64(t))
		}
		// next generates the next admissible job, if any.
		next := func() (job, bool) {
			for head < len(frontier) {
				e := &frontier[head]
				if e.next == n {
					head++
					// Compact only once the consumed prefix is at least half
					// the slice, so each element is copied O(1) times.
					if head == len(frontier) {
						frontier, head = frontier[:0], 0
					} else if head*2 >= len(frontier) {
						frontier, head = append(frontier[:0], frontier[head:]...), 0
					}
					continue
				}
				if cfg.MaxQueries > 0 && admitted >= cfg.MaxQueries {
					skipped += remaining
					remaining = 0
					capped = true
					frontier, head = nil, 0
					return job{}, false
				}
				entry := cfg.Entries[e.next]
				e.next++
				remaining--
				name := entry + "." + e.parent
				// Key by the name relative to the root domain. For depth 1 that
				// is the entry itself, so no extra string is retained.
				key := entry
				if e.depth > 1 {
					key = name[:len(name)-len(cfg.Domain)-1]
				}
				if _, dup := visited[key]; dup {
					continue
				}
				visited[key] = struct{}{}
				admitted++
				return job{domain: name, depth: e.depth}, true
			}
			return job{}, false
		}
		closeJobs := func() {
			if skipped > 0 {
				select {
				case events <- Event{Kind: EventNotice, Notice: NoticeCap, Message: fmt.Sprintf(
					"query cap reached (-max-queries %d); skipped %d additional jobs", cfg.MaxQueries, skipped)}:
				case <-ctx.Done():
				}
			}
			close(jobs)
		}

		var ready job
		haveReady := false
		for {
			if !haveReady {
				ready, haveReady = next()
				publishTotal()
			}
			if !haveReady && pending == 0 {
				closeJobs()
				return
			}
			var out chan job
			if haveReady {
				out = jobs
			}
			select {
			case <-ctx.Done():
				closeJobs()
				return
			case parent := <-enqueue:
				if capped {
					skipped += n
					continue
				}
				frontier = append(frontier, expansion{parent: parent.domain, depth: parent.depth + 1})
				remaining += n
				publishTotal()
			case out <- ready:
				haveReady = false
				pending++
			case <-completed:
				pending--
			}
		}
	}()

	// Worker pool.
	workers := workerCount(cfg, maxDepth)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				processJob(ctx, cfg, j, maxDepth, jobLimiter, events, enqueue, &processed, &found, &stats, cancel, &guardOnce, fingerprint, wc)
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
	// EventDone is the abort/finish signal. CLI Finish and TUI aborted=true both
	// wait for it after cancel, so this send must not be select-guarded on
	// ctx.Done(): once ctx is cancelled that select is a coin-flip drop.
	// Contract: consumers drain until close. See #23.
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
func processJob(ctx context.Context, cfg Config, j job, maxDepth int, limiter *dns.RateLimiter, events chan<- Event, enqueue chan<- job, processed, found *int64, st *counters, cancel context.CancelFunc, guardOnce *sync.Once, fp *fingerprint, wc *wildcardCache) {
	if ctx.Err() != nil {
		return
	}
	if err := limiter.Wait(ctx); err != nil {
		return
	}

	var outcome dns.Outcome
	var records []dns.Record
	switch {
	case cfg.resolveHook != nil:
		records, outcome = cfg.resolveHook(ctx, j.domain)
	case cfg.Simulate:
		var ok bool
		records, ok = dns.SimulateResolve(j.domain, cfg.HitRate, cfg.Seed, cfg.logf(), cfg.Types)
		if ok {
			outcome = dns.OutcomeFound
		} else {
			outcome = dns.OutcomeNXDomain
		}
	default:
		records, outcome = dns.ResolveDomainWithRetry(ctx, cfg.Resolver, j.domain, cfg.Timeout, cfg.logf(), cfg.Attempts, cfg.Types)
	}

	// A lookup cut short by cancellation (Ctrl+C, or the reliability guard's own
	// cancel) says nothing about the resolver. Leave it out of every counter so
	// an interrupt cannot inflate the failure rate or trip the guard (#42).
	if outcome == dns.OutcomeCanceled || (outcome != dns.OutcomeFound && ctx.Err() != nil) {
		return
	}

	if outcome == dns.OutcomeFound && isWildcardAnswer(ctx, cfg, fp, j.domain, records) {
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
	// Unguarded: CLI and TUI drain until close. A ctx.Done() guard here would
	// only matter for a consumer that stops reading with a full buffer.
	events <- Event{Kind: EventResult, Domain: j.domain, Records: records}

	if cfg.Recursive && j.depth < maxDepth {
		if !cfg.Simulate && cfg.resolveHook == nil {
			isWild, err := wc.isWildcard(ctx, cfg, j.domain)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				events <- Event{Kind: EventNotice, Notice: NoticeSkip, Message: "skipping recursive expansion of " + j.domain + ": wildcard check failed: " + err.Error()}
				return
			}
			if isWild {
				events <- Event{Kind: EventNotice, Notice: NoticeSkip, Message: "wildcard DNS at " + j.domain + "; skipping recursive expansion"}
				return
			}
		}
		// Hand the parent to the dispatcher, which generates its children.
		select {
		case enqueue <- j:
		case <-ctx.Done():
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
