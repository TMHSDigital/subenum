// Package scan runs a subdomain scan: it validates options, dispatches
// candidate names to a worker pool, filters wildcard answers and reports
// results and statistics as events.
package scan

import (
	"context"
	"fmt"
	"net"
	"sort"
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
	Verbose     bool     // log every lookup; through Logf when set, else unsynchronized to stderr
	Logf        dns.Logf // receives verbose lines when Verbose is set
	Rate        int      // max DNS messages per second on the wire, all workers combined (0 = unlimited)
	// AutoRate halves the rate when most recent lookups fail, and raises
	// it again once they succeed, instead of letting the reliability guard
	// abort at the first sign of rate-limiting (#220).
	AutoRate   bool
	Types      []string // record types to look up (A, AAAA, CNAME, NS, MX, TXT); empty = A,AAAA
	Recursive  bool     // enumerate subdomains of discovered subdomains
	Depth      int      // max recursion depth (1 = no recursion)
	NoAbort    bool     // keep scanning after the reliability guard fires
	MaxQueries int      // cap on admitted candidate names (jobs), not wire queries (0 = unlimited)
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
	// TakeoverProviders are the takeover-prone services CNAME targets are
	// matched against; nil is the built-in list (#219).
	TakeoverProviders dns.TakeoverProviders

	// Resuming an interrupted scan (#73): ResumeFrom skips the wordlist
	// entries before it (Stats.RootDone of the interrupted run), and
	// ResumeParents are names found before the interrupt whose children a
	// recursive scan still has to expand.
	ResumeFrom    int
	ResumeParents []string
	Resolver      *net.Resolver // reused across lookups; nil means scan.Run constructs one
	// Pool, when set, spreads candidate lookups over several resolvers (#69).
	// Every pool hit is re-validated against Resolver (the trusted
	// -dns-server), whose answer is the one reported; preflight and wildcard
	// checks also use Resolver.
	Pool *dns.Pool

	// resolveHook, if set, replaces the simulation and live lookups (see resolve).
	// Tests inject classified outcomes through this field without network I/O.
	resolveHook func(ctx context.Context, domain string) ([]dns.Record, dns.Outcome)

	scope    *scope             // built from Exclude by Run
	takeover *dns.TakeoverCache // one CNAME-target lookup per target per scan (#121)
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

// resolve is the one lookup of a name that the scan workers, Verify and the
// wildcard near-miss probes share (#163): the test hook when set, else the
// simulation, else the trusted resolver with retries. The resolver pool is not
// consulted here; processJob layers it on top for candidate names.
func (c Config) resolve(ctx context.Context, name string, logf dns.Logf) ([]dns.Record, dns.Outcome) {
	switch {
	case c.resolveHook != nil:
		return c.resolveHook(ctx, name)
	case c.Simulate:
		records, ok := dns.Simulation{HitRate: c.HitRate, Seed: c.Seed}.Resolve(name, logf, c.Types)
		if ok {
			return records, dns.OutcomeFound
		}
		return nil, dns.OutcomeNXDomain
	default:
		return c.lookup(logf).Resolve(ctx, name)
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

// Stats is a snapshot of per-outcome query counters. Populated on EventDone.
type Stats struct {
	Found            int64
	NXDomain         int64
	Timeout          int64
	Refused          int64
	Other            int64
	WildcardFiltered int64

	// Run facts for the quality report (#70); not part of Sum.
	QueriesSent int64 // DNS queries dialed, retries included (0 when simulated)
	Skipped     int64 // candidates not tested because -max-queries or -max-duration was reached
	Excluded    int64 // candidates not tested because -exclude put them out of scope
	PoolHits    int64 // names a pool resolver said exist (-r)
	Confirmed   int64 // pool hits the trusted resolver confirmed
	Unconfirmed int64 // pool hits the trusted resolver said do not exist
	Takeover    int64 // results flagged as subdomain-takeover candidates
	Internal    int64 // results with a non-public address (Result.Internal, #218)
	// RootDone is the resume point: every wordlist entry before this index
	// has been fully looked up (#73). Entries at or after it may also be
	// done; resuming repeats at most one chunk (maxChunk jobs) per worker,
	// since workers report their jobs a chunk at a time (#184).
	RootDone    int64
	Aborted     bool         // the reliability guard cancelled the scan
	Expired     bool         // Deadline (-max-duration) stopped admission; Skipped counts what it left
	Wildcard    bool         // the root domain is a wildcard (scanned under -force)
	Fingerprint []dns.Record // final wildcard fingerprint, empty when none

	// Inconclusive lookups (#217). Retried counts the names the
	// RetryInconclusive pass looked up again, and Recovered the ones that
	// then got an answer: their first outcome (timeout, refused, other)
	// moves to the new one, so the outcome counters still add up to the
	// names tested. Inconclusive lists, sorted, the names whose lookup is
	// still a timeout, refusal or failure at the end of the scan.
	Retried      int64
	Recovered    int64
	Inconclusive []string

	// AutoRate (#220): how many times the rate was halved, and the rate in
	// queries per second when the scan ended (0 = unlimited). Both are 0
	// without AutoRate.
	RateBackoffs int64
	FinalRate    int64
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
	skipped          atomic.Int64
	excluded         atomic.Int64
	poolHits         atomic.Int64
	confirmed        atomic.Int64
	unconfirmed      atomic.Int64
	takeover         atomic.Int64
	internal         atomic.Int64
	rootDone         atomic.Int64
	retried          atomic.Int64
	recovered        atomic.Int64
	aborted          atomic.Bool
	expired          atomic.Bool
}

func (c *counters) add(o dns.Outcome) { c.counter(o).Add(1) }

// counter is the outcome's counter; an unknown outcome counts as other.
func (c *counters) counter(o dns.Outcome) *atomic.Int64 {
	switch o {
	case dns.OutcomeFound:
		return &c.found
	case dns.OutcomeNXDomain:
		return &c.nxdomain
	case dns.OutcomeTimeout:
		return &c.timeout
	case dns.OutcomeRefused:
		return &c.refused
	}
	return &c.other
}

// inconclusive reports whether a lookup outcome leaves the name's existence
// unknown: a timeout, a refusal or another failure (#217).
func inconclusive(o dns.Outcome) bool {
	return o == dns.OutcomeTimeout || o == dns.OutcomeRefused || o == dns.OutcomeOther
}

// pendingLookup is a job whose lookup was inconclusive, and that outcome.
type pendingLookup struct {
	j       job
	outcome dns.Outcome
}

// pendingList collects the inconclusive lookups of a scan, for the retry
// pass and Stats.Inconclusive (#217). Workers add to it concurrently.
type pendingList struct {
	mu    sync.Mutex
	items []pendingLookup
}

func (l *pendingList) add(j job, o dns.Outcome) {
	l.mu.Lock()
	l.items = append(l.items, pendingLookup{j: j, outcome: o})
	l.mu.Unlock()
}

// take empties the list and returns what it held.
func (l *pendingList) take() []pendingLookup {
	l.mu.Lock()
	defer l.mu.Unlock()
	items := l.items
	l.items = nil
	return items
}

// names returns the listed names, sorted.
func (l *pendingList) names() []string {
	l.mu.Lock()
	out := make([]string, 0, len(l.items))
	for _, it := range l.items {
		out = append(out, it.j.domain)
	}
	l.mu.Unlock()
	sort.Strings(out)
	return out
}

func (c *counters) snapshot() Stats {
	return Stats{
		Found:            c.found.Load(),
		NXDomain:         c.nxdomain.Load(),
		Timeout:          c.timeout.Load(),
		Refused:          c.refused.Load(),
		Other:            c.other.Load(),
		WildcardFiltered: c.wildcardFiltered.Load(),
		Skipped:          c.skipped.Load(),
		Excluded:         c.excluded.Load(),
		PoolHits:         c.poolHits.Load(),
		Confirmed:        c.confirmed.Load(),
		Unconfirmed:      c.unconfirmed.Load(),
		Takeover:         c.takeover.Load(),
		Internal:         c.internal.Load(),
		RootDone:         c.rootDone.Load(),
		Retried:          c.retried.Load(),
		Recovered:        c.recovered.Load(),
		Aborted:          c.aborted.Load(),
		Expired:          c.expired.Load(),
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

	is, _, err := cfg.lookup(nil).CheckWildcard(ctx, parent)
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

func (f *fingerprint) add(recs []dns.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range recs {
		f.set[dns.RecordKey(r)] = struct{}{}
	}
}

// records returns the fingerprint's records in a stable order.
func (f *fingerprint) records() []dns.Record {
	f.mu.RLock()
	keys := make([]string, 0, len(f.set))
	for k := range f.set {
		keys = append(keys, k)
	}
	f.mu.RUnlock()
	sort.Strings(keys)
	out := make([]dns.Record, 0, len(keys))
	for _, k := range keys {
		typ, val, _ := strings.Cut(k, "\x00")
		out = append(out, dns.Record{Type: typ, Value: val})
	}
	return out
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
		if _, ok := f.set[dns.RecordKey(r)]; ok {
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
		recs, _ := cfg.resolve(ctx, dns.RandomLabel()+"."+parent, nil)
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
	root   int // index into cfg.Entries for a depth-1 job, else -1
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

// EventKind categorises a scan event.
type EventKind int

// Event kinds.
const (
	// EventResult reports a resolved subdomain.
	EventResult   EventKind = iota
	EventProgress           // progress update
	EventNotice             // informational notice; see Event.Notice
	// EventError reports a problem. Usually the scan then stops and its
	// EventDone has Stopped set; after the reliability guard (with NoAbort)
	// the scan goes on.
	EventError
	// EventDone is always the last event, sent exactly once (#99).
	EventDone
)

// NoticeKind says what an EventNotice is about, so consumers can style or
// filter notices without parsing the message (#68).
type NoticeKind int

// Notice kinds.
const (
	// NoticeWildcard means wildcard DNS was detected, or its check failed
	// under -force.
	NoticeWildcard NoticeKind = iota + 1
	NoticeCap                 // -max-queries or -max-duration reached; candidates skipped
	NoticeCeiling             // recursive scan may generate very many queries
	NoticeSkip                // a recursive branch was not expanded
	NoticeRate                // AutoRate changed the query rate (#220)
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
	case NoticeRate:
		return "rate"
	}
	return "notice"
}

// Result is one resolved subdomain. It is the single per-result type that
// flows from the engine (Event.Result) to the writers, which embed it in
// output.Result (#162), so its JSON tags and field order are part of the
// structured output formats: change them only together with those formats.
type Result struct {
	Subdomain string       `json:"subdomain"`
	Records   []dns.Record `json:"records"` // of the looked-up types
	// Simulated is set on every result of a simulated scan, so invented
	// names can never pass for real recon output once saved or piped (#53).
	Simulated bool `json:"simulated,omitempty"`
	// Takeover is a DNS-only subdomain-takeover hint ("dangling",
	// "provider:<name>" or "dangling:<name>"), see dns.TakeoverHint;
	// verify it by hand (#71).
	Takeover string `json:"takeover_candidate,omitempty"`
	// Internal is the most notable non-public scope among the name's
	// addresses ("loopback", "unspecified", "link-local", "private" or
	// "cgnat"), see dns.InternalScope; empty when every address is public.
	// A public name that answers with one leaks internal addressing (#218).
	Internal string `json:"internal_address,omitempty"`
}

// Event is emitted on the events channel during a scan.
type Event struct {
	Kind      EventKind
	Notice    NoticeKind // EventNotice: what the notice is about
	Result    Result     // EventResult: the resolved subdomain and its records
	Processed int64      // EventProgress
	Total     int64      // EventProgress
	Found     int64      // EventProgress / EventDone
	Message   string     // EventError / EventNotice
	Stats     Stats      // EventDone: per-outcome counters
	// Stopped is set on EventDone when the scan ended before testing any
	// candidate: after an EventError (out of scope, recursion ceiling, failed
	// preflight or wildcard check, wildcard zone without Force) or when ctx
	// was cancelled during those checks. Its Stats cover only the checks.
	Stopped bool
}

// Run executes the subdomain scan, sending events to the provided channel.
// The caller must close or cancel ctx to abort early.
// Run closes events when the scan completes.
func Run(ctx context.Context, cfg Config, events chan<- Event) {
	defer close(events)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cfg.Attempts = max(cfg.Attempts, 1)

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
	if cfg.AutoRate {
		limiter = dns.NewAdjustableRateLimiter(cfg.Rate)
	}
	if cfg.Resolver == nil {
		cfg.Resolver = dns.NewResolver(cfg.Timeout, cfg.DNSServer)
	}
	// DoT and DoH connections kept for reuse are not held past the scan (#113).
	defer dns.CloseIdleConnections(cfg.Resolver)
	var jobLimiter *dns.RateLimiter
	if cfg.Simulate || cfg.resolveHook != nil {
		jobLimiter = limiter
	} else {
		ctx = dns.WithLimiter(ctx, limiter)
	}
	var queriesSent atomic.Int64
	ctx = dns.WithQueryCounter(ctx, &queriesSent)
	// Every scan ends with exactly one EventDone (#99): one that stops before
	// the candidates sends it here, with Stopped set, before close(events).
	doneSent := false
	defer func() {
		if !doneSent {
			events <- Event{Kind: EventDone, Stopped: true, Total: int64(len(cfg.Entries)), Stats: Stats{QueriesSent: queriesSent.Load()}}
		}
	}()
	wildcardRoot := false

	// Out-of-scope names are never queried (#87). A target that is itself
	// out of scope, or whose every candidate would be, is refused outright.
	sc := newScope(cfg.Exclude)
	cfg.scope = sc
	cfg.takeover = &dns.TakeoverCache{Providers: cfg.TakeoverProviders}
	if sc.excluded(cfg.Domain) || sc.subtreeExcluded(cfg.Domain) {
		events <- Event{Kind: EventError, Message: "refusing to scan " + cfg.Domain + ": it is out of scope ({exclude})"}
		return
	}

	if cfg.Recursive {
		ceiling := RecursionCeiling(len(cfg.Entries), maxDepth)
		if ceiling > recursionRefuseCeiling && cfg.MaxQueries == 0 && !cfg.Force {
			events <- Event{Kind: EventError, Message: fmt.Sprintf(
				"refusing to start: {recursive} {depth} %d with %d entries can generate up to %.1e queries; set {max_queries} or {force}",
				maxDepth, len(cfg.Entries), ceiling)}
			return
		}
		consider := "Consider {max_queries}."
		if maxDepth > 1 {
			consider = fmt.Sprintf("Consider {depth} %d or {max_queries}.", maxDepth-1)
		}
		events <- Event{Kind: EventNotice, Notice: NoticeCeiling, Message: fmt.Sprintf(
			"Warning: {recursive} {depth} %d with %d entries can generate up to %.1e queries.\n%s",
			maxDepth, len(cfg.Entries), ceiling, consider)}
	}

	if !cfg.Simulate && cfg.resolveHook == nil {
		// Retried like any other lookup, so one dropped packet cannot abort a
		// scan that -attempts would otherwise complete (#57).
		_, outcome := cfg.resolve(ctx, cfg.Domain, nil)
		if ctx.Err() != nil {
			return // interrupted during preflight: not a resolver failure
		}
		if outcome != dns.OutcomeFound && outcome != dns.OutcomeNXDomain {
			msg := fmt.Sprintf("resolver %s failed preflight for %s: %s after %d attempt(s)", cfg.DNSServer, cfg.Domain, outcome, cfg.Attempts)
			events <- Event{Kind: EventError, Message: msg}
			return
		}
		// An apex the trusted resolver answers is the first canary for
		// checking that pool members do not hide existing names (#105).
		if outcome == dns.OutcomeFound && cfg.Pool != nil {
			cfg.Pool.AddCanary(cfg.Domain)
		}
	}

	fingerprint := newFingerprint(nil)
	wc := &wildcardCache{known: make(map[string]bool)}

	// Wildcard detection (skip in simulation mode).
	if !cfg.Simulate {
		isWildcard, fp, err := cfg.lookup(nil).FingerprintWildcard(ctx, cfg.Domain)
		if ctx.Err() != nil {
			return // interrupted during wildcard probes
		}
		// An inconclusive check is never "no wildcard": under a real wildcard
		// every candidate would resolve and flood the results (#47). -force
		// scans anyway, but without a fingerprint to filter with.
		if err != nil && !cfg.Force {
			events <- Event{Kind: EventError, Message: "wildcard detection failed: " + err.Error() + "; results could not be filtered. Use {force} to scan anyway."}
			return
		}
		if err != nil {
			events <- Event{Kind: EventNotice, Notice: NoticeWildcard, Message: "WARNING: wildcard detection failed (" + err.Error() + "); scanning without wildcard filtering because of {force}"}
		}
		fingerprint.add(fp)
		if isWildcard {
			wildcardRoot = true
			msg := "WARNING: Wildcard DNS detected - all subdomains resolve for " + cfg.Domain
			events <- Event{Kind: EventNotice, Notice: NoticeWildcard, Message: msg}
			if !cfg.Force {
				events <- Event{Kind: EventError, Message: "Results would be meaningless. Use {force} to scan anyway."}
				return
			}
		}
	}

	var wg sync.WaitGroup

	// Work queue channels. The dispatcher owns the lifecycle: it tracks
	// outstanding work and closes jobs only once every dispatched job has
	// completed. Workers send found parents on enqueue (before signalling
	// completed) and the dispatcher expands them into depth-capped children.
	// Jobs go out in small chunks and both hand-off channels are buffered,
	// so workers and the dispatcher rarely block on each other (#184); each
	// job still reports its own completion as soon as it is done.
	workers := workerCount(cfg, maxDepth)
	jobs := make(chan []job, handoffPerWorker*workers)
	enqueue := make(chan job)
	completed := make(chan []completion, handoffPerWorker*workers)

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

	// The dispatcher hands out candidates and closes jobs once every
	// dispatched job has completed, or ctx is cancelled (see dispatcher).
	go newDispatcher(cfg, maxDepth).run(ctx, workers, jobs, enqueue, completed, &total, &stats, events)

	// Worker pool.
	st := &scanState{
		cfg: cfg, maxDepth: maxDepth, limiter: jobLimiter, events: events, enqueue: enqueue,
		processed: &processed, found: &found, stats: &stats, cancel: cancel, guardOnce: &guardOnce,
		fp: fingerprint, wc: wc, pending: &pendingList{},
	}
	if cfg.AutoRate {
		sent := queriesSent.Load
		if jobLimiter != nil {
			// Simulated and hooked jobs send nothing; one job is one slot.
			sent = func() int64 { return atomic.LoadInt64(&processed) }
		}
		st.auto = newAutoRate(limiter, sent)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for chunk := range jobs {
				done := make([]completion, 0, len(chunk))
				for _, j := range chunk {
					c := completion{root: j.root, skipped: true}
					// One taken after the budget ran out is skipped, like the
					// candidates the dispatcher never handed out (#190).
					if !cfg.pastDeadline() {
						c = completion{root: j.root, finished: st.processJob(ctx, j)}
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
		}()
	}

	wg.Wait()
	if cfg.RetryInconclusive {
		st.retryPending(ctx, workers)
	}
	// Stop the ticker goroutine and wait for it to fully exit before emitting
	// EventDone, so the deferred close(events) can never race an in-flight
	// ticker send.
	close(tickerDone)
	<-tickerStopped

	snap := stats.snapshot()
	snap.QueriesSent = queriesSent.Load()
	snap.Wildcard = wildcardRoot
	snap.Fingerprint = fingerprint.records()
	snap.Inconclusive = st.pending.names()
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
		Processed: atomic.LoadInt64(&processed),
		Total:     atomic.LoadInt64(&total),
		Found:     atomic.LoadInt64(&found),
		Stats:     snap,
	}
}

// scanState is what every worker shares during one scan (#159).
type scanState struct {
	cfg       Config
	maxDepth  int
	limiter   *dns.RateLimiter // paces simulated and hooked jobs; nil for live lookups, which pace per query
	events    chan<- Event
	enqueue   chan<- job // found parents, for the dispatcher to expand
	processed *int64     // atomic
	found     *int64     // atomic
	stats     *counters
	cancel    context.CancelFunc // the reliability guard's abort
	guardOnce *sync.Once
	fp        *fingerprint
	wc        *wildcardCache
	pending   *pendingList // inconclusive lookups (#217)
	auto      *autoRate    // the AutoRate controller; nil without AutoRate (#220)
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
	cfg, st, maxDepth := s.cfg, s.stats, s.maxDepth
	if ctx.Err() != nil {
		return false
	}
	if err := s.limiter.Wait(ctx); err != nil {
		return false
	}

	var outcome dns.Outcome
	var records []dns.Record
	if cfg.Pool != nil && !cfg.Simulate && cfg.resolveHook == nil {
		records, outcome = resolveViaPool(ctx, cfg, j.domain, st)
	} else {
		records, outcome = cfg.resolve(ctx, j.domain, cfg.logf())
	}

	// A lookup cut short by cancellation (Ctrl+C, or the reliability guard's own
	// cancel) says nothing about the resolver. Leave it out of every counter so
	// an interrupt cannot inflate the failure rate or trip the guard (#42).
	if settle(ctx, outcome) == dns.OutcomeCanceled {
		return false
	}

	if outcome == dns.OutcomeFound && isWildcardAnswer(ctx, cfg, s.fp, j.domain, records) {
		st.wildcardFiltered.Add(1)
		s.observe(false)
		s.checkReliability(atomic.AddInt64(s.processed, 1))
		return true
	}

	st.add(outcome)
	if inconclusive(outcome) {
		s.pending.add(j, outcome)
	}
	s.observe(inconclusive(outcome))
	s.checkReliability(atomic.AddInt64(s.processed, 1))

	if outcome != dns.OutcomeFound {
		return true
	}

	s.report(ctx, j.domain, records)

	if cfg.Recursive && j.depth < maxDepth {
		// The wildcard probe would query inside the branch, so an out-of-scope
		// subtree is not probed; the dispatcher counts its children as excluded.
		if !cfg.Simulate && cfg.resolveHook == nil && !cfg.scope.subtreeExcluded(j.domain) {
			isWild, err := s.wc.isWildcard(ctx, cfg, j.domain)
			if ctx.Err() != nil {
				return true
			}
			if err != nil {
				s.events <- Event{Kind: EventNotice, Notice: NoticeSkip, Message: "skipping recursive expansion of " + j.domain + ": wildcard check failed: " + err.Error()}
				return true
			}
			if isWild {
				s.events <- Event{Kind: EventNotice, Notice: NoticeSkip, Message: "wildcard DNS at " + j.domain + "; skipping recursive expansion"}
				return true
			}
		}
		// Hand the parent to the dispatcher, which generates its children.
		select {
		case s.enqueue <- j:
		case <-ctx.Done():
		}
	}
	return true
}

// report counts a found name and sends it as a result.
func (s *scanState) report(ctx context.Context, name string, records []dns.Record) {
	cfg := s.cfg
	atomic.AddInt64(s.found, 1)
	// Unguarded: CLI and TUI drain until close. A ctx.Done() guard here would
	// only matter for a consumer that stops reading with a full buffer.
	// A CNAME result gets a DNS-only takeover hint; its target is resolved
	// with the trusted resolver. Simulated records are never checked.
	takeover := ""
	if !cfg.Simulate && cfg.resolveHook == nil {
		takeover = cfg.takeover.Hint(ctx, cfg.lookup(nil), records)
	}
	if takeover != "" {
		s.stats.takeover.Add(1)
	}
	// Simulated addresses are invented (in 10.0.0.0/8), so they say nothing.
	internal := ""
	if !cfg.Simulate {
		internal = dns.InternalScope(records)
	}
	if internal != "" {
		s.stats.internal.Add(1)
	}
	s.events <- Event{Kind: EventResult, Result: Result{Subdomain: name, Records: records, Simulated: cfg.Simulate, Takeover: takeover, Internal: internal}}
}

// retryPending is the RetryInconclusive pass (#217): once every candidate
// has been tried, each inconclusive lookup is tried once more against the
// trusted resolver by up to workers goroutines. It does not run after the
// reliability guard aborted the scan, after an interrupt or once the
// Deadline has passed; names it does not get to stay inconclusive.
func (s *scanState) retryPending(ctx context.Context, workers int) {
	if ctx.Err() != nil || s.stats.aborted.Load() || s.cfg.pastDeadline() {
		return
	}
	items := s.pending.take()
	ch := make(chan pendingLookup)
	var wg sync.WaitGroup
	for range min(workers, len(items)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range ch {
				s.retry(ctx, it)
			}
		}()
	}
	for i, it := range items {
		if ctx.Err() != nil || s.cfg.pastDeadline() {
			for _, rest := range items[i:] {
				s.pending.add(rest.j, rest.outcome)
			}
			break
		}
		ch <- it
	}
	close(ch)
	wg.Wait()
}

// retry looks an inconclusive name up once more. An answer, positive or
// negative, replaces the first outcome in the counters; a name found is
// reported (unless it is a wildcard answer) but not expanded. A name still
// without an answer keeps its first outcome and stays pending.
func (s *scanState) retry(ctx context.Context, it pendingLookup) {
	cfg, st := s.cfg, s.stats
	if err := s.limiter.Wait(ctx); err != nil {
		s.pending.add(it.j, it.outcome)
		return
	}
	records, outcome := cfg.resolve(ctx, it.j.domain, cfg.logf())
	if outcome = settle(ctx, outcome); outcome == dns.OutcomeCanceled {
		s.pending.add(it.j, it.outcome)
		return
	}
	st.retried.Add(1)
	if inconclusive(outcome) {
		s.pending.add(it.j, it.outcome)
		return
	}
	st.recovered.Add(1)
	st.counter(it.outcome).Add(-1)
	if outcome == dns.OutcomeFound && isWildcardAnswer(ctx, cfg, s.fp, it.j.domain, records) {
		st.wildcardFiltered.Add(1)
		return
	}
	st.add(outcome)
	if outcome == dns.OutcomeFound {
		s.report(ctx, it.j.domain, records)
	}
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
func resolveViaPool(ctx context.Context, cfg Config, name string, st *counters) ([]dns.Record, dns.Outcome) {
	trustedLookup := cfg.lookup(cfg.logf())
	a := cfg.Pool.Resolve(ctx, trustedLookup, name)
	if a.NoResolver {
		// Every pool member was caught lying: the trusted resolver answers.
		return trustedLookup.Resolve(ctx, name)
	}
	if a.Outcome != dns.OutcomeFound {
		return nil, a.Outcome
	}
	st.poolHits.Add(1)
	records, trusted := trustedLookup.Resolve(ctx, name)
	switch trusted {
	case dns.OutcomeFound:
		st.confirmed.Add(1)
		cfg.Pool.AddCanary(name)
	case dns.OutcomeNXDomain:
		st.unconfirmed.Add(1)
	}
	cfg.Pool.Disagree(a, trusted)
	return records, trusted
}

// checkReliability runs the reliability guard once processed lookups are
// counted: past the failure threshold it reports once, and aborts the scan
// unless NoAbort is set.
func (s *scanState) checkReliability(processed int64) {
	cfg, st := s.cfg, s.stats
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
		s.events <- Event{Kind: EventError, Message: msg}
		if !cfg.NoAbort {
			st.aborted.Store(true)
			s.cancel()
		}
	})
}
