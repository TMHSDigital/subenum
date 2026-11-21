// Package scan runs a subdomain scan: it validates options, dispatches
// candidate names to a worker pool, filters wildcard answers and reports
// results and statistics as events.
package scan

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/validate"
)

const (
	reliabilityMinJobs     = 200
	reliabilityFailPercent = 20
	recursionRefuseCeiling = 1e7
)

// Config holds all parameters needed to run a subdomain scan.
type Config struct {
	Domain string
	// Entries are the labels to try, unique and normalized (wordlist.Build
	// and Prepare guarantee both); a non-recursive scan does not dedupe them
	// again (#248).
	Entries []string
	// RecursiveEntries are the labels a recursive scan tries under each name
	// it finds, at depth 2 and below (-recursive-w, #403); unique and
	// normalized like Entries. Nil means Entries.
	RecursiveEntries []string
	Concurrency      int
	Timeout          time.Duration
	DNSServer        string
	Simulate         bool
	HitRate          int
	Seed             uint64 // simulation seed: the same seed reproduces the same simulated results
	Attempts         int
	Force            bool
	Verbose          bool     // log every lookup; through Logf when set, else unsynchronized to stderr
	Logf             dns.Logf // receives verbose lines when Verbose is set
	Rate             int      // max DNS messages per second on the wire, all workers combined (0 = unlimited)
	// AutoRate halves the rate when most recent lookups fail, and raises
	// it again once they succeed, instead of letting the reliability guard
	// abort at the first sign of rate-limiting (#220).
	AutoRate  bool
	Types     []string // record types to look up (A, AAAA, CNAME, NS, MX, TXT, SRV); empty = A,AAAA
	Recursive bool     // enumerate subdomains of discovered subdomains
	// FollowRecords also tests the names under the target that a found
	// name's CNAME, MX or NS records point at, once each, unless they are
	// already candidates (#432). They are tested like any candidate, within
	// MaxQueries and Deadline, and not expanded by Recursive.
	FollowRecords bool
	Depth         int  // max recursion depth (1 = no recursion)
	NoAbort       bool // keep scanning after the reliability guard fires
	MaxQueries    int  // cap on admitted candidate names (jobs), not wire queries (0 = unlimited)
	// Deadline stops admitting candidates at this instant (-max-duration,
	// #190); lookups in flight finish and the rest are counted as skipped.
	// It is an instant rather than a duration so one budget can span every
	// target of a -dL run. Zero means no limit.
	Deadline time.Time
	Exclude  []string // out-of-scope names and *.parent patterns; never queried (#87)
	// RetryInconclusive looks up once more, after every candidate has been
	// tried, each name whose lookup timed out, was refused or failed (#217).
	// The retry goes to the trusted resolver, never the pool. A name it
	// resolves is reported like any other, but not expanded by Recursive.
	RetryInconclusive bool
	// ListInconclusive fills Stats.Inconclusive. Without it the names are
	// only counted, and kept no longer than the retry pass needs them, so a
	// scan against a failing resolver does not hold a name per failed
	// lookup for a list nobody reads (#300).
	ListInconclusive bool
	// TakeoverProviders are the takeover-prone services CNAME targets are
	// matched against; nil is the built-in list (#219).
	TakeoverProviders dns.TakeoverProviders

	// Resuming an interrupted scan (#73): ResumeFrom skips the wordlist
	// entries before it (Stats.RootDone of the interrupted run), and
	// ResumeParents are names found before the interrupt whose children a
	// recursive scan still has to expand.
	ResumeFrom    int
	ResumeParents []string
	// ResumeFollow are the FollowRecords targets of the names found before
	// the interrupt that are not among them, queued again (#432).
	ResumeFollow []string
	// RetryPrior are the names the earlier part of a resumed scan left for
	// its retry pass (its Stats.Pending); under RetryInconclusive this scan's
	// retry pass looks them up (#315).
	RetryPrior []Pending
	Resolver   *net.Resolver // reused across lookups; nil means scan.Run constructs one
	// Pool, when set, spreads candidate lookups over several resolvers (#69).
	// Every pool hit is re-validated against Resolver (the trusted
	// -dns-server), whose answer is the one reported; preflight and wildcard
	// checks also use Resolver.
	Pool *dns.Pool
	// ZoneServer, when set ("host:port"), receives the delegation queries
	// meant for the target zone's name servers, which are then not looked
	// up: a lab run sends them to its local server, which answers for the
	// zone, so nothing leaves the machine (#406).
	ZoneServer string

	// resolveHook, if set, replaces the simulation and live lookups (see resolve).
	// Tests inject classified outcomes through this field without network I/O.
	resolveHook func(ctx context.Context, domain string) ([]dns.Record, dns.Outcome)

	scope    *scope             // built from Exclude by Run
	takeover *dns.TakeoverCache // one CNAME-target lookup per target per scan (#121)
	// resumeDepth is each resumed parent's recursion level (see
	// resumeDepths), found by Run before the parents are gated, so a
	// parent's level does not depend on which of its ancestors pass.
	resumeDepth map[string]int
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

// lookup is the trusted resolver's lookup settings, logging through logf.
func (c Config) lookup(logf dns.Logf) dns.Lookup {
	return dns.Lookup{Resolver: c.Resolver, Timeout: c.Timeout, Attempts: c.Attempts, Types: c.Types, Logf: logf}
}

// live reports whether lookups go to real resolvers: neither simulated nor
// replaced by the test hook (#331).
func (c Config) live() bool {
	return !c.Simulate && c.resolveHook == nil
}

// resolve is the one lookup of a name that the scan workers, Verify and the
// wildcard near-miss probes share (#163): the test hook when set, else the
// simulation, else the trusted resolver with retries. The resolver pool is not
// consulted here; processJob layers it on top for candidate names.
func (c Config) resolve(ctx context.Context, name string, logf dns.Logf) ([]dns.Record, dns.Outcome) {
	records, outcome, _ := c.resolvePartial(ctx, name, logf)
	return records, outcome
}

// resolvePartial is resolve that also says when a found name's answer is
// partial: a requested type failed on every attempt (#357).
func (c Config) resolvePartial(ctx context.Context, name string, logf dns.Logf) ([]dns.Record, dns.Outcome, bool) {
	switch {
	case c.resolveHook != nil:
		records, outcome := c.resolveHook(ctx, name)
		return records, outcome, false
	case c.Simulate:
		records, ok := dns.Simulation{HitRate: c.HitRate, Seed: c.Seed}.Resolve(name, logf, c.Types)
		if ok {
			return records, dns.OutcomeFound, false
		}
		return nil, dns.OutcomeNXDomain, false
	default:
		return c.lookup(logf).ResolvePartial(ctx, name)
	}
}

// settle reports a lookup that did not find the name while ctx was cancelled
// as OutcomeCanceled: a lookup cut short says nothing about the resolver or
// the name (#42).
func settle(ctx context.Context, o dns.Outcome) dns.Outcome {
	if o != dns.OutcomeFound && ctx.Err() != nil {
		return dns.OutcomeCanceled
	}
	return o
}

// RecursionCeiling returns the theoretical job count for a recursive scan:
// sum over d=1..depth of n^d, as a float so large wordlists do not overflow.
func RecursionCeiling(n, depth int) float64 {
	return RecursionCeilingOf(n, n, depth)
}

// RecursionCeilingOf is RecursionCeiling for a scan that tries n entries at
// depth 1 and m under each found name below it (-recursive-w, #403): sum over
// d=1..depth of n*m^(d-1).
func RecursionCeilingOf(n, m, depth int) float64 {
	if n <= 0 || depth <= 0 {
		return 0
	}
	var total, term float64
	term = float64(n)
	for d := 1; d <= depth; d++ {
		total += term
		term *= float64(max(m, 0))
	}
	return total
}

// recursionCeiling is the job ceiling of cfg's entries to depth.
func recursionCeiling(cfg Config, depth int) float64 {
	return RecursionCeilingOf(len(cfg.Entries), len(cfg.entriesAt(2)), depth)
}

// entriesAt returns the labels an expansion at depth tries: Entries at depth
// 1, and RecursiveEntries below it when they are given (#403).
func (c Config) entriesAt(depth int) []string {
	if depth > 1 && c.RecursiveEntries != nil {
		return c.RecursiveEntries
	}
	return c.Entries
}

// workerCount caps the pool at the most jobs the scan can produce, so a huge
// -t on a short wordlist does not spawn millions of idle goroutines (#58).
func workerCount(cfg Config, maxDepth int) int {
	depth := 1
	if cfg.Recursive {
		depth = maxDepth
	}
	work := recursionCeiling(cfg, depth)
	if cfg.MaxQueries > 0 {
		work = min(work, float64(cfg.MaxQueries))
	}
	return max(1, int(min(float64(cfg.Concurrency), work)))
}

// job is a single unit of work: a fully qualified domain to test and its depth
// in the recursion tree (initial entries are depth 1).
type job struct {
	domain   string
	depth    int
	root     int  // index into cfg.Entries for a depth-1 job, else -1
	followed bool // a found name's record named it (FollowRecords, #432)
}

// completion reports a job back to the dispatcher. finished is false when
// the lookup was cut short by cancellation, so it does not count toward the
// resume point. skipped means the worker took the job after the Deadline and
// never looked it up.
type completion struct {
	root     int
	finished bool
	skipped  bool
}

// pastDeadline reports whether the -max-duration budget has run out (#190).
func (c Config) pastDeadline() bool {
	return !c.Deadline.IsZero() && !time.Now().Before(c.Deadline)
}

// expansion is a pending run of candidates: every cfg.Entries[next:] prepended
// to parent, at the given depth. The root expansion has parent cfg.Domain.
type expansion struct {
	parent string
	depth  int
	next   int
}

// Run executes the subdomain scan, sending events to the provided channel.
// The caller must close or cancel ctx to abort early.
// Run closes events when the scan completes.
func Run(ctx context.Context, cfg Config, events chan<- Event) {
	defer close(events)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cfg.Attempts = max(cfg.Attempts, 1)
	maxDepth := max(cfg.Depth, 1)

	// One limiter paces the whole scan. Live lookups carry it on ctx and take a
	// slot per DNS query they send (every record type, every retry, wildcard
	// probes and the preflight), so -rate bounds wire queries, not names (#32).
	// Simulated and hooked lookups have no wire traffic and take one slot per job.
	limiter := dns.NewRateLimiter(cfg.Rate)
	if cfg.AutoRate {
		limiter = dns.NewAdjustableRateLimiter(cfg.Rate)
	}
	if cfg.Resolver == nil {
		if normalized, err := validate.NormalizeDNSServer(cfg.DNSServer); err == nil {
			cfg.DNSServer = normalized
		}
		cfg.Resolver = dns.NewResolver(cfg.Timeout, cfg.DNSServer)
	}
	// DoT and DoH connections kept for reuse are not held past the scan
	// (#113), nor are the -r pool members' sockets (#252).
	defer dns.CloseIdleConnections(cfg.Resolver)
	defer cfg.Pool.CloseIdleConnections()
	var jobLimiter *dns.RateLimiter
	if !cfg.live() {
		jobLimiter = limiter
	} else {
		ctx = dns.WithLimiter(ctx, limiter)
	}
	var queriesSent atomic.Int64
	ctx = dns.WithQueryCounter(ctx, &queriesSent)
	// Every scan ends with exactly one EventDone (#99): one that stops before
	// the candidates sends it here, with Stopped set, before close(events).
	doneSent, failed := false, false
	defer func() {
		if !doneSent {
			events <- Event{Kind: EventDone, Stopped: true, Failed: failed, Total: int64(len(cfg.Entries)), Stats: Stats{QueriesSent: queriesSent.Load()}}
		}
	}()

	cfg.scope = newScope(cfg.Exclude)
	cfg.takeover = &dns.TakeoverCache{Providers: cfg.TakeoverProviders, Skip: cfg.scope.excluded}
	checksStarted := time.Now()
	wildcardRoot, fingerprint, ok, fatal := preflight(ctx, &cfg, maxDepth, events)
	if !ok {
		failed = fatal
		return
	}
	if !cfg.Deadline.IsZero() && checksStarted.Before(cfg.Deadline) {
		// The preflight and wildcard probes do not use up the budget: under a
		// low -rate they can take all of a short one, and a -resume probes
		// again, so it would never test a name (#340). A budget already spent
		// when the scan started (a later -dL target) stays spent.
		cfg.Deadline = cfg.Deadline.Add(time.Since(checksStarted))
	}
	cfg.resumeDepth = resumeDepths(cfg)

	st := &scanState{
		cfg: cfg, maxDepth: maxDepth, limiter: jobLimiter, events: events,
		cancel: cancel, fp: fingerprint, wc: &wildcardCache{known: make(map[string]bool)},
		parent: newParentZone(cfg),
	}
	if cfg.ListInconclusive || cfg.RetryInconclusive {
		st.pending = &pendingList{}
	}
	if cfg.RetryInconclusive {
		// Names an earlier part of a resumed scan left for its retry pass
		// (#315). Their first outcome is in that part's counters, so a
		// recovery here moves it in this part's, which the merge sums.
		for _, p := range cfg.RetryPrior {
			st.pending.add(pendingLookup{name: p.Name, root: -1, outcome: p.Outcome, prior: true})
		}
	}
	st.rootStart = min(max(cfg.ResumeFrom, 0), len(cfg.Entries))
	st.rootOutcome = make([]uint8, len(cfg.Entries)-st.rootStart)
	st.total.Store(int64(len(cfg.Entries)))
	if cfg.AutoRate {
		sent := queriesSent.Load
		if jobLimiter != nil {
			// Simulated and hooked jobs send nothing; one job is one slot.
			sent = st.processed.Load
		}
		st.auto = newAutoRate(limiter, sent)
	}

	// Work queue channels. The dispatcher owns the lifecycle: it tracks
	// outstanding work and closes jobs only once every dispatched job has
	// completed. Workers send found parents on enqueue (before signalling
	// completed) and the dispatcher expands them into depth-capped children.
	// Jobs go out in small chunks and both hand-off channels are buffered,
	// so workers and the dispatcher rarely block on each other (#184); a
	// worker reports the completions of a whole chunk in one send once the
	// chunk is done.
	workers := workerCount(cfg, maxDepth)
	jobs := make(chan []job, handoffPerWorker*workers)
	enqueue := make(chan job)
	follow := make(chan []string) // FollowRecords targets, sent like found parents (#432)
	completed := make(chan []completion, handoffPerWorker*workers)
	st.enqueue, st.follow = enqueue, follow

	stopTicker := st.startTicker(ctx)
	cfg.ResumeParents = st.gateResumeParents(ctx, workers)
	// The dispatcher hands out candidates and closes jobs once every
	// dispatched job has completed, or ctx is cancelled (see dispatcher).
	disp := newDispatcher(cfg, maxDepth)
	disp.rootOutcome = st.rootOutcome // it marks the entries out of scope
	go disp.run(ctx, workers, jobs, handoff{enqueue: enqueue, follow: follow, completed: completed}, &st.total, &st.stats, events)
	st.runWorkers(ctx, workers, jobs, completed)
	if cfg.RetryInconclusive {
		st.retryPending(ctx, workers)
	}
	// After the retry pass, which moves the names it recovers (#374).
	repeat := st.repeat()
	// Stop the ticker and wait for it to fully exit before emitting
	// EventDone, so the deferred close(events) can never race an in-flight
	// ticker send.
	stopTicker()

	snap := st.stats.snapshot()
	snap.QueriesSent = queriesSent.Load()
	snap.Wildcard = wildcardRoot
	snap.Fingerprint = fingerprint.records()
	st.finishPending(&snap, &repeat)
	if st.parent != nil {
		snap.ParentChecks, snap.ParentQueries = st.parent.checks.Load(), st.parent.queries.Load()
	}
	snap.Repeat = repeat
	if st.auto != nil {
		snap.RateBackoffs, snap.FinalRate = st.auto.result()
	}
	// EventDone is the abort/finish signal. CLI Finish and TUI aborted=true both
	// wait for it after cancel, so this send must not be select-guarded on
	// ctx.Done(): once ctx is cancelled that select is a coin-flip drop.
	// Contract: consumers drain until close. See #23.
	doneSent = true
	events <- Event{
		Kind:      EventDone,
		Processed: st.processed.Load(),
		Total:     st.total.Load(),
		Found:     st.found.Load(),
		Stats:     snap,
		// The guard's abort is the one fatal error past the preflight.
		Failed: snap.Aborted,
	}
}

// preflight runs the checks a scan passes before any candidate is tested:
// the scope of the target (#87), the recursion ceiling, the resolver
// preflight and wildcard detection. It reports whether the root is a
// wildcard zone and the wildcard fingerprint to filter with. On false the
// scan must stop: preflight has sent the fatal EventError explaining why
// (fatal is then set), or ctx was cancelled, and Run's deferred EventDone
// (Stopped) ends the scan.
func preflight(ctx context.Context, cfg *Config, maxDepth int, events chan<- Event) (wildcardRoot bool, fp *fingerprint, ok, fatal bool) {
	// Out-of-scope names are never queried (#87). A target that is itself
	// out of scope, or whose every candidate would be, is refused outright.
	if cfg.scope.targetExcluded(cfg.Domain) {
		events <- Event{Kind: EventError, Fatal: true, Message: "refusing to scan " + cfg.Domain + ": it is out of scope ({exclude})"}
		return false, nil, false, true
	}

	if cfg.Recursive {
		ceiling := recursionCeiling(*cfg, maxDepth)
		entries := fmt.Sprintf("%d entries", len(cfg.Entries))
		if cfg.RecursiveEntries != nil {
			entries += fmt.Sprintf(" (%d below depth 1)", len(cfg.RecursiveEntries))
		}
		if ceiling > recursionRefuseCeiling && cfg.MaxQueries == 0 && !cfg.Force {
			events <- Event{Kind: EventError, Fatal: true, Message: fmt.Sprintf(
				"refusing to start: {recursive} {depth} %d with %s can generate up to %.1e queries; set {max_queries} or {force}",
				maxDepth, entries, ceiling)}
			return false, nil, false, true
		}
		consider := "Consider {max_queries}."
		if maxDepth > 1 {
			consider = fmt.Sprintf("Consider {depth} %d or {max_queries}.", maxDepth-1)
		}
		events <- Event{Kind: EventNotice, Notice: NoticeCeiling, Message: fmt.Sprintf(
			"Warning: {recursive} {depth} %d with %s can generate up to %.1e queries.\n%s",
			maxDepth, entries, ceiling, consider)}
	}

	if cfg.live() {
		// Retried like any other lookup, so one dropped packet cannot abort a
		// scan that -attempts would otherwise complete (#57).
		_, outcome := cfg.resolve(ctx, cfg.Domain, nil)
		if ctx.Err() != nil {
			return false, nil, false, false // interrupted during preflight: not a resolver failure
		}
		if outcome != dns.OutcomeFound && outcome != dns.OutcomeNXDomain {
			msg := fmt.Sprintf("resolver %s failed preflight for %s: %s after %d attempt(s)", dns.DisplayServer(cfg.DNSServer), cfg.Domain, outcome, cfg.Attempts)
			events <- Event{Kind: EventError, Fatal: true, Message: msg}
			return false, nil, false, true
		}
		// An apex the trusted resolver answers is the first canary for
		// checking that pool members do not hide existing names (#105).
		if outcome == dns.OutcomeFound && cfg.Pool != nil {
			cfg.Pool.AddCanary(cfg.Domain)
		}
	}

	fp = newFingerprint(nil)

	// Wildcard detection (skip in simulation mode). It checks Simulate alone,
	// not live(): the probes go through the trusted resolver, which the test
	// hook does not replace, so a hooked scan without Simulate still probes
	// Resolver (tests point it at a local server, or set Simulate too).
	if !cfg.Simulate {
		isWildcard, probed, err := cfg.lookup(nil).FingerprintWildcard(ctx, cfg.Domain)
		if ctx.Err() != nil {
			return false, nil, false, false // interrupted during wildcard probes
		}
		// An inconclusive check is never "no wildcard": under a real wildcard
		// every candidate would resolve and flood the results (#47). -force
		// scans anyway, but without a fingerprint to filter with.
		if err != nil && !cfg.Force {
			events <- Event{Kind: EventError, Fatal: true, Message: "wildcard detection failed: " + err.Error() + "; results could not be filtered. Use {force} to scan anyway."}
			return false, nil, false, true
		}
		if err != nil {
			events <- Event{Kind: EventNotice, Notice: NoticeWildcard, Message: "WARNING: wildcard detection failed (" + err.Error() + "); scanning without wildcard filtering because of {force}"}
		}
		fp.add(probed)
		if isWildcard {
			wildcardRoot = true
			msg := "WARNING: Wildcard DNS detected - all subdomains resolve for " + cfg.Domain
			events <- Event{Kind: EventNotice, Notice: NoticeWildcard, Message: msg}
			if !cfg.Force {
				events <- Event{Kind: EventError, Fatal: true, Message: "Results would be meaningless. Use {force} to scan anyway."}
				return false, nil, false, true
			}
		}
	}
	return wildcardRoot, fp, true, false
}

// startTicker sends an EventProgress every second until ctx is done or the
// returned stop function is called. stop waits for the ticker goroutine to
// exit, so no progress send is still pending once it returns.
func (s *scanState) startTicker(ctx context.Context) (stop func()) {
	tickerDone := make(chan struct{})
	tickerStopped := make(chan struct{})
	ticker := time.NewTicker(time.Second)
	go func() {
		defer close(tickerStopped)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ev := Event{Kind: EventProgress, Processed: s.processed.Load(), Total: s.total.Load(), Found: s.found.Load()}
				select {
				case s.events <- ev:
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
	return func() {
		close(tickerDone)
		<-tickerStopped
	}
}

// runWorkers runs the worker pool until the dispatcher closes jobs, and
// returns once every worker has exited. Each worker processes a chunk of
// jobs and reports its completions in one send.
func (s *scanState) runWorkers(ctx context.Context, workers int, jobs <-chan []job, completed chan<- []completion) {
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for chunk := range jobs {
				done := make([]completion, 0, len(chunk))
				for _, j := range chunk {
					c := completion{root: j.root, skipped: true}
					// One taken after the budget ran out is skipped, like the
					// candidates the dispatcher never handed out (#190).
					if !s.cfg.pastDeadline() {
						c = completion{root: j.root, finished: s.processJob(ctx, j)}
					}
					done = append(done, c)
				}
				// The buffer holds several reports per worker, so this send
				// rarely waits, and after an interrupt a finished chunk is
				// still reported when there is room, for the resume point.
				select {
				case completed <- done:
				default:
					select {
					case completed <- done:
					case <-ctx.Done():
					}
				}
			}
		})
	}
	wg.Wait()
}

// scanState is what every worker shares during one scan (#159).
type scanState struct {
	cfg       Config
	maxDepth  int
	limiter   *dns.RateLimiter // paces simulated and hooked jobs; nil for live lookups, which pace per query
	events    chan<- Event
	enqueue   chan<- job      // found parents, for the dispatcher to expand
	follow    chan<- []string // FollowRecords targets, for the dispatcher to queue (#432)
	processed atomic.Int64
	found     atomic.Int64
	total     atomic.Int64 // the progress total; the dispatcher updates it as recursion adds work
	stats     counters
	cancel    context.CancelFunc // the reliability guard's abort
	guardOnce sync.Once
	fp        *fingerprint
	wc        *wildcardCache
	pending   *pendingList // inconclusive lookups (#217); nil when nothing reads them (#300)
	auto      *autoRate    // the AutoRate controller; nil without AutoRate (#220)
	parent    *parentZone  // asks the zone's name servers about SERVFAIL names (#406); nil unless NS is looked up live

	// For Stats.Repeat (#341): how each wordlist entry from rootStart on
	// ended (a repeat code, written by the one worker that looked it up, or
	// by the dispatcher for one out of scope), and per code the lookups below
	// depth 1.
	rootStart   int
	rootOutcome []uint8
	deep        [repeatCodes]atomic.Int64
}

// handoffPerWorker sizes the jobs and completed buffers, per worker (#184).
const handoffPerWorker = 4

// observe feeds one lookup to the AutoRate controller and reports a rate
// change as a notice.
func (s *scanState) observe(failed bool) {
	if s.auto == nil {
		return
	}
	if msg := s.auto.observe(failed); msg != "" {
		s.events <- Event{Kind: EventNotice, Notice: NoticeRate, Message: msg}
	}
}

// processJob resolves a single job and, on success, optionally enqueues
// depth-capped children for recursive enumeration.
func (s *scanState) processJob(ctx context.Context, j job) (finished bool) {
	cfg, st, maxDepth := s.cfg, &s.stats, s.maxDepth
	if ctx.Err() != nil {
		return false
	}
	if err := s.limiter.Wait(ctx); err != nil {
		return false
	}

	var outcome dns.Outcome
	var records []dns.Record
	var partial bool
	if cfg.Pool != nil && cfg.live() {
		records, outcome, partial = resolveViaPool(ctx, cfg, j.domain, st)
	} else {
		records, outcome, partial = cfg.resolvePartial(ctx, j.domain, cfg.logf())
	}

	// A lookup cut short by cancellation (Ctrl+C, or the reliability guard's own
	// cancel) says nothing about the resolver. Leave it out of every counter so
	// an interrupt cannot inflate the failure rate or trip the guard (#42).
	if settle(ctx, outcome) == dns.OutcomeCanceled {
		return false
	}

	if outcome == dns.OutcomeFound && isWildcardAnswer(ctx, cfg, s.fp, j.domain, records) {
		st.wildcardFiltered.Add(1)
		s.recordRepeat(j, repeatWildcard)
		s.observe(false)
		s.checkReliability(s.processed.Add(1))
		return true
	}

	// A name that ends SERVFAIL may be a subzone whose every name server is
	// gone: the zone's own name servers still name them (#406).
	delegated := false
	if outcome == dns.OutcomeOther {
		if ns, ok := s.danglingDelegation(ctx, j.domain); ok {
			records, outcome, partial, delegated = ns, dns.OutcomeFound, false, true
		} else if settle(ctx, outcome) == dns.OutcomeCanceled {
			return false
		}
	}

	st.add(outcome)
	s.recordRepeat(j, repeatCode(outcome))
	if inconclusive(outcome) {
		s.pending.add(pendingOf(j, outcome))
	}
	s.observe(inconclusive(outcome))
	s.checkReliability(s.processed.Add(1))

	if outcome != dns.OutcomeFound {
		return true
	}

	s.report(ctx, j.domain, records, partial, j.followed)

	if cfg.FollowRecords {
		// Sent before the job completes, as a parent is, so the dispatcher
		// cannot finish before it has queued them.
		if targets := followTargets(cfg, records); len(targets) > 0 {
			select {
			case s.follow <- targets:
			case <-ctx.Done():
			}
		}
	}

	// Every name under a dangling delegation fails the same way, so it is
	// not expanded.
	if cfg.Recursive && !delegated && j.depth < maxDepth && s.expandable(ctx, j.domain) {
		// Hand the parent to the dispatcher, which generates its children.
		select {
		case s.enqueue <- j:
		case <-ctx.Done():
		}
	}
	return true
}

// expandable reports whether a recursive scan may expand a found parent. A
// wildcard branch, or one whose wildcard check was inconclusive, is skipped
// with a notice.
func (s *scanState) expandable(ctx context.Context, parent string) bool {
	cfg := s.cfg
	// The wildcard probe would query inside the branch, so an out-of-scope
	// subtree is not probed; the dispatcher counts its children as excluded.
	if !cfg.live() || cfg.scope.subtreeExcluded(parent) {
		return true
	}
	isWild, err := s.wc.isWildcard(ctx, cfg, parent)
	if ctx.Err() != nil {
		return false
	}
	if err != nil {
		s.events <- Event{Kind: EventNotice, Notice: NoticeSkip, Message: "skipping recursive expansion of " + parent + ": wildcard check failed: " + err.Error()}
		return false
	}
	if isWild {
		s.events <- Event{Kind: EventNotice, Notice: NoticeSkip, Message: "wildcard DNS at " + parent + "; skipping recursive expansion"}
		return false
	}
	return true
}

// gateResumeParents returns the resumed parents the dispatcher may expand:
// the ones in range (see resumeParent) that pass the same check as a parent
// found by this run (#296). The checks run on up to workers goroutines.
func (s *scanState) gateResumeParents(ctx context.Context, workers int) []string {
	if !s.cfg.Recursive {
		return nil
	}
	var parents []string
	for _, p := range s.cfg.ResumeParents {
		if name, _, ok := resumeParent(s.cfg, p, s.maxDepth); ok {
			parents = append(parents, name)
		}
	}
	keep := make([]bool, len(parents))
	var next atomic.Int64
	var wg sync.WaitGroup
	for range min(workers, len(parents)) {
		wg.Go(func() {
			for {
				i := int(next.Add(1)) - 1
				if i >= len(parents) || ctx.Err() != nil {
					return
				}
				// Past the time budget nothing is probed: the dispatcher
				// counts the children as skipped.
				keep[i] = s.cfg.pastDeadline() || s.expandable(ctx, parents[i])
			}
		})
	}
	wg.Wait()
	gated := parents[:0]
	for i, p := range parents {
		if keep[i] {
			gated = append(gated, p)
		}
	}
	return gated
}

// followTargets returns the names records point at that a FollowRecords scan
// tests (#432): CNAME, MX and NS targets under the target, lower case,
// without the target itself and without the ones -exclude rules out.
func followTargets(cfg Config, records []dns.Record) []string {
	var out []string
	for _, r := range records {
		var name string
		switch r.Type {
		case "CNAME", "NS":
			name = r.Value
		case "MX":
			fields := strings.Fields(r.Value) // "<preference> <host>"
			if len(fields) == 0 {
				continue
			}
			name = fields[len(fields)-1]
		default:
			continue
		}
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if !strings.HasSuffix(name, "."+cfg.Domain) || cfg.scope.excluded(name) || slices.Contains(out, name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// report counts a found name and sends it as a result. followed marks a
// name a FollowRecords scan took from another result's records.
func (s *scanState) report(ctx context.Context, name string, records []dns.Record, partial, followed bool) {
	cfg := s.cfg
	s.found.Add(1)
	if partial {
		s.stats.partial.Add(1)
	}
	// Unguarded: CLI and TUI drain until close. A ctx.Done() guard here would
	// only matter for a consumer that stops reading with a full buffer.
	// A CNAME result gets a DNS-only takeover hint; its target is resolved
	// with the trusted resolver, unless it is out of scope (#316). Simulated
	// records are never checked.
	takeover := ""
	if cfg.live() {
		takeover = cfg.takeover.Hint(ctx, cfg.lookup(nil), records)
	}
	if takeover != "" {
		s.stats.takeover.Add(1)
	}
	// Simulated addresses are invented (in 10.0.0.0/8), so they say nothing.
	// Simulate alone, not live(): the check sends nothing, so a hooked scan's
	// records are checked like live ones.
	internal := ""
	if !cfg.Simulate {
		internal = dns.InternalScope(records)
	}
	if internal != "" {
		s.stats.internal.Add(1)
	}
	s.events <- Event{Kind: EventResult, Followed: followed, Result: Result{Subdomain: name, Records: records, Simulated: cfg.Simulate, Takeover: takeover, Internal: internal, Partial: partial}}
}

// resolveViaPool looks name up through the resolver pool and re-validates a
// hit against the trusted resolver, so a pool member that lies (a poisoned or
// hijacking resolver) cannot inject results (#69). The trusted answer is the
// one reported. A pool hit the trusted resolver cannot confirm because its
// own lookup failed counts as that failure, not as a silent drop.
//
// Negative answers are guarded inside the pool (canary checks and second
// opinions, #105); the trusted resolver's verdict on each hit is fed back so
// a member that hid the name or injected it is flagged, and every confirmed
// name becomes a canary.
func resolveViaPool(ctx context.Context, cfg Config, name string, st *counters) ([]dns.Record, dns.Outcome, bool) {
	trustedLookup := cfg.lookup(cfg.logf())
	a := cfg.Pool.Resolve(ctx, trustedLookup, name)
	if a.NoResolver {
		// Every pool member was caught lying: the trusted resolver answers.
		return trustedLookup.ResolvePartial(ctx, name)
	}
	if a.Outcome != dns.OutcomeFound {
		return nil, a.Outcome, false
	}
	st.poolHits.Add(1)
	records, trusted, partial := trustedLookup.ResolvePartial(ctx, name)
	switch trusted {
	case dns.OutcomeFound:
		st.confirmed.Add(1)
		cfg.Pool.AddCanary(name)
	case dns.OutcomeNXDomain:
		st.unconfirmed.Add(1)
	}
	cfg.Pool.Disagree(a, trusted)
	return records, trusted, partial
}

// checkReliability runs the reliability guard once processed lookups are
// counted: past the failure threshold it reports once, and aborts the scan
// unless NoAbort is set.
func (s *scanState) checkReliability(processed int64) {
	cfg, st := s.cfg, &s.stats
	if processed < reliabilityMinJobs {
		return
	}
	if s.auto != nil && !s.auto.gaveUp() {
		return // AutoRate slows down instead, until it runs out of room (#220)
	}
	snap := st.snapshot()
	failures := snap.failures()
	if failures*100 <= processed*int64(reliabilityFailPercent) {
		return
	}
	s.guardOnce.Do(func() {
		rate := float64(failures) * 100 / float64(processed)
		verb := "aborting scan"
		if cfg.NoAbort {
			verb = "warning"
		}
		msg := fmt.Sprintf("%s: %.0f%% of %d queries failed (timeout/refused/other); likely resolver rate-limiting at {concurrency} %d and {rate} %d",
			verb, rate, processed, cfg.Concurrency, cfg.Rate)
		s.events <- Event{Kind: EventError, Fatal: !cfg.NoAbort, Message: msg}
		if !cfg.NoAbort {
			st.aborted.Store(true)
			s.cancel()
		}
	})
}
