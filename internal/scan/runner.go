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
	Domain string
	// Entries are the labels to try, unique and normalized (wordlist.Build
	// and Prepare guarantee both); a non-recursive scan does not dedupe them
	// again (#248).
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
//
// The CLI's -resume state file stores Stats as JSON, so the tags are a file
// format: they spell the field names as they were when the format was fixed,
// and renaming a field must keep its tag (or bump the state file's version)
// (#331).
type Stats struct {
	Found            int64 `json:"Found"`
	NXDomain         int64 `json:"NXDomain"`
	Timeout          int64 `json:"Timeout"`
	Refused          int64 `json:"Refused"`
	Other            int64 `json:"Other"`
	WildcardFiltered int64 `json:"WildcardFiltered"`

	// Run facts for the quality report (#70); not part of Sum.
	QueriesSent int64 `json:"QueriesSent"` // DNS queries dialed, retries included (0 when simulated)
	Skipped     int64 `json:"Skipped"`     // candidates not tested because -max-queries or -max-duration was reached
	Excluded    int64 `json:"Excluded"`    // candidates not tested because -exclude put them out of scope
	PoolHits    int64 `json:"PoolHits"`    // names a pool resolver said exist (-r)
	Confirmed   int64 `json:"Confirmed"`   // pool hits the trusted resolver confirmed
	Unconfirmed int64 `json:"Unconfirmed"` // pool hits the trusted resolver said do not exist
	Takeover    int64 `json:"Takeover"`    // results flagged as subdomain-takeover candidates
	Internal    int64 `json:"Internal"`    // results with a non-public address (Result.Internal, #218)
	// RootDone is the resume point: every wordlist entry before this index
	// has been fully looked up (#73). Entries at or after it may also be
	// done; resuming repeats at most one chunk (maxChunk jobs) per worker,
	// since workers report their jobs a chunk at a time (#184).
	RootDone    int64        `json:"RootDone"`
	Aborted     bool         `json:"Aborted"`     // the reliability guard cancelled the scan
	Expired     bool         `json:"Expired"`     // Deadline (-max-duration) stopped admission; Skipped counts what it left
	Wildcard    bool         `json:"Wildcard"`    // the root domain is a wildcard (scanned under -force)
	Fingerprint []dns.Record `json:"Fingerprint"` // final wildcard fingerprint, empty when none

	// Inconclusive lookups (#217). Retried counts the names the
	// RetryInconclusive pass looked up again, and Recovered the ones that
	// then got an answer: their first outcome (timeout, refused, other)
	// moves to the new one, so the outcome counters still add up to the
	// names tested. Inconclusive lists, sorted, the names whose lookup is
	// still a timeout, refusal or failure at the end of the scan; it is nil
	// without Config.ListInconclusive (#300).
	Retried      int64    `json:"Retried"`
	Recovered    int64    `json:"Recovered"`
	Inconclusive []string `json:"Inconclusive"`

	// AutoRate (#220): how many times the rate was halved, and the rate in
	// queries per second when the scan ended (0 = unlimited). Both are 0
	// without AutoRate.
	RateBackoffs int64 `json:"RateBackoffs"`
	FinalRate    int64 `json:"FinalRate"`

	// Repeat is the part of the counters above that a resume from RootDone
	// does again; not saved in the state file (#341).
	Repeat Repeat `json:"-"`
	// Pending lists, under Config.RetryInconclusive, the inconclusive names
	// the retry pass did not get to (the scan stopped first) and a resume
	// does not look up again anyway, for Config.RetryPrior of the resumed
	// scan (#315). The CLI saves it apart from Stats.
	Pending []Pending `json:"-"`
}

// Repeat counts the work of a scan that a resume from its RootDone repeats
// (#341): the wordlist entries at or past RootDone that were looked up or
// found out of scope (a chunk reported late, or names past a budget stop),
// and every lookup and exclusion below depth 1, since a resumed recursive
// scan expands every saved parent again. A stopped scan's counters, less
// these, plus the resumed scan's, count each name once.
type Repeat struct {
	Processed        int64 // lookups, wildcard-filtered ones included
	Found            int64
	NXDomain         int64
	Timeout          int64
	Refused          int64
	Other            int64
	WildcardFiltered int64
	Excluded         int64
	// Inconclusive lists the names of Stats.Inconclusive that are repeated.
	Inconclusive []string
}

// Repeat codes: how one name ended, for Stats.Repeat (#341).
const (
	repeatNone uint8 = iota
	repeatExcluded
	repeatWildcard
	repeatFound
	repeatNXDomain
	repeatTimeout
	repeatRefused
	repeatOther
	repeatCodes
)

// repeatCode is the repeat code of a lookup outcome.
func repeatCode(o dns.Outcome) uint8 {
	switch o {
	case dns.OutcomeFound:
		return repeatFound
	case dns.OutcomeNXDomain:
		return repeatNXDomain
	case dns.OutcomeTimeout:
		return repeatTimeout
	case dns.OutcomeRefused:
		return repeatRefused
	}
	return repeatOther
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

// pendingLookup is a name whose lookup was inconclusive, and that outcome.
// A depth-1 name is kept as its index into cfg.Entries and rebuilt on
// demand, so the list does not keep the job's name string alive (#300);
// only a recursive child, which has no such index, keeps its name.
type pendingLookup struct {
	name    string // a recursive child's full name; "" for a depth-1 name
	root    int    // index into cfg.Entries for a depth-1 name, else -1
	outcome dns.Outcome
	prior   bool // from Config.RetryPrior: an earlier part of a resumed scan looked it up (#315)
	retried bool // the retry pass looked it up again, still without an answer
}

// Pending is a name whose lookup was inconclusive and that the retry pass
// has not looked up again yet, with the outcome it got (#315).
type Pending struct {
	Name    string
	Outcome dns.Outcome
}

// pendingOf is the list entry for job j, whose lookup ended in o.
func pendingOf(j job, o dns.Outcome) pendingLookup {
	if j.root >= 0 {
		return pendingLookup{root: j.root, outcome: o}
	}
	return pendingLookup{name: j.domain, root: -1, outcome: o}
}

// domain is the name that was looked up.
func (p pendingLookup) domain(cfg *Config) string {
	if p.root >= 0 {
		return cfg.Entries[p.root] + "." + cfg.Domain
	}
	return p.name
}

// pendingList collects the inconclusive lookups of a scan, for the retry
// pass and Stats.Inconclusive (#217). Workers add to it concurrently. A nil
// list collects nothing: the scan has no reader for the names (#300).
type pendingList struct {
	mu    sync.Mutex
	items []pendingLookup
}

func (l *pendingList) add(it pendingLookup) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.items = append(l.items, it)
	l.mu.Unlock()
}

// take empties the list and returns what it held.
func (l *pendingList) take() []pendingLookup {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	items := l.items
	l.items = nil
	return items
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
	if covered || !overlaps || !cfg.live() {
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
	// the scan goes on. Event.Fatal tells the two apart.
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
	// Fatal is set on an EventError that ends the scan. The one error
	// without it is the reliability guard's warning under NoAbort (#308).
	Fatal bool
	// Failed is set on EventDone when the scan failed: a fatal EventError
	// was sent, or the reliability guard aborted the scan. A cancelled scan
	// has not failed. Consumers read this instead of working it out from
	// the errors they saw and their own copy of NoAbort (#308).
	Failed bool
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
	completed := make(chan []completion, handoffPerWorker*workers)
	st.enqueue = enqueue

	stopTicker := st.startTicker(ctx)
	cfg.ResumeParents = st.gateResumeParents(ctx, workers)
	// The dispatcher hands out candidates and closes jobs once every
	// dispatched job has completed, or ctx is cancelled (see dispatcher).
	disp := newDispatcher(cfg, maxDepth)
	disp.rootOutcome = st.rootOutcome // it marks the entries out of scope
	go disp.run(ctx, workers, jobs, enqueue, completed, &st.total, &st.stats, events)
	st.runWorkers(ctx, workers, jobs, completed)
	// Before the retry pass, which runs only when nothing is left to resume.
	repeat := st.repeat()
	if cfg.RetryInconclusive {
		st.retryPending(ctx, workers)
	}
	// Stop the ticker and wait for it to fully exit before emitting
	// EventDone, so the deferred close(events) can never race an in-flight
	// ticker send.
	stopTicker()

	snap := st.stats.snapshot()
	snap.QueriesSent = queriesSent.Load()
	snap.Wildcard = wildcardRoot
	snap.Fingerprint = fingerprint.records()
	st.finishPending(&snap, &repeat)
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
	if cfg.scope.excluded(cfg.Domain) || cfg.scope.subtreeExcluded(cfg.Domain) {
		events <- Event{Kind: EventError, Fatal: true, Message: "refusing to scan " + cfg.Domain + ": it is out of scope ({exclude})"}
		return false, nil, false, true
	}

	if cfg.Recursive {
		ceiling := RecursionCeiling(len(cfg.Entries), maxDepth)
		if ceiling > recursionRefuseCeiling && cfg.MaxQueries == 0 && !cfg.Force {
			events <- Event{Kind: EventError, Fatal: true, Message: fmt.Sprintf(
				"refusing to start: {recursive} {depth} %d with %d entries can generate up to %.1e queries; set {max_queries} or {force}",
				maxDepth, len(cfg.Entries), ceiling)}
			return false, nil, false, true
		}
		consider := "Consider {max_queries}."
		if maxDepth > 1 {
			consider = fmt.Sprintf("Consider {depth} %d or {max_queries}.", maxDepth-1)
		}
		events <- Event{Kind: EventNotice, Notice: NoticeCeiling, Message: fmt.Sprintf(
			"Warning: {recursive} {depth} %d with %d entries can generate up to %.1e queries.\n%s",
			maxDepth, len(cfg.Entries), ceiling, consider)}
	}

	if cfg.live() {
		// Retried like any other lookup, so one dropped packet cannot abort a
		// scan that -attempts would otherwise complete (#57).
		_, outcome := cfg.resolve(ctx, cfg.Domain, nil)
		if ctx.Err() != nil {
			return false, nil, false, false // interrupted during preflight: not a resolver failure
		}
		if outcome != dns.OutcomeFound && outcome != dns.OutcomeNXDomain {
			msg := fmt.Sprintf("resolver %s failed preflight for %s: %s after %d attempt(s)", cfg.DNSServer, cfg.Domain, outcome, cfg.Attempts)
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
	enqueue   chan<- job // found parents, for the dispatcher to expand
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

	// For Stats.Repeat (#341): how each wordlist entry from rootStart on
	// ended (a repeat code, written by the one worker that looked it up, or
	// by the dispatcher for one out of scope), and per code the lookups below
	// depth 1.
	rootStart   int
	rootOutcome []uint8
	deep        [repeatCodes]atomic.Int64
}

// recordRepeat notes how job j ended, for Stats.Repeat.
func (s *scanState) recordRepeat(j job, code uint8) {
	if j.root < 0 {
		s.deep[code].Add(1)
		return
	}
	if i := j.root - s.rootStart; i >= 0 && i < len(s.rootOutcome) {
		s.rootOutcome[i] = code
	}
}

// repeated reports whether a resume from the scan's RootDone looks up the
// inconclusive name it again.
func (s *scanState) repeated(it pendingLookup) bool {
	return !it.prior && (it.root < 0 || int64(it.root) >= s.stats.rootDone.Load())
}

// finishPending empties the pending list into snap: the inconclusive names
// and the repeated ones among them, and the names a resumed scan's retry
// pass must still look up.
func (s *scanState) finishPending(snap *Stats, repeat *Repeat) {
	cfg := &s.cfg
	items := s.pending.take()
	if cfg.ListInconclusive {
		all := make([]string, 0, len(items))
		for _, it := range items {
			name := it.domain(cfg)
			all = append(all, name)
			if s.repeated(it) {
				repeat.Inconclusive = append(repeat.Inconclusive, name)
			}
		}
		sort.Strings(all)
		sort.Strings(repeat.Inconclusive)
		snap.Inconclusive = all
	}
	if cfg.RetryInconclusive {
		for _, it := range items {
			if !it.retried && !s.repeated(it) {
				snap.Pending = append(snap.Pending, Pending{Name: it.domain(cfg), Outcome: it.outcome})
			}
		}
	}
}

// repeat tallies Stats.Repeat once every worker has exited. Every exclusion
// is repeated but those of entries before RootDone.
func (s *scanState) repeat() Repeat {
	var n [repeatCodes]int64
	for code := range n {
		n[code] = s.deep[code].Load()
	}
	from := int(s.stats.rootDone.Load()) - s.rootStart
	var kept int64
	for i, code := range s.rootOutcome {
		switch {
		case i >= from:
			n[code]++
		case code == repeatExcluded:
			kept++
		}
	}
	r := Repeat{Found: n[repeatFound], NXDomain: n[repeatNXDomain], Timeout: n[repeatTimeout],
		Refused: n[repeatRefused], Other: n[repeatOther], WildcardFiltered: n[repeatWildcard]}
	r.Processed = r.Found + r.NXDomain + r.Timeout + r.Refused + r.Other + r.WildcardFiltered
	r.Excluded = max(s.stats.excluded.Load()-kept, 0)
	return r
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
	if cfg.Pool != nil && cfg.live() {
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
		s.recordRepeat(j, repeatWildcard)
		s.observe(false)
		s.checkReliability(s.processed.Add(1))
		return true
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

	s.report(ctx, j.domain, records)

	if cfg.Recursive && j.depth < maxDepth && s.expandable(ctx, j.domain) {
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

// report counts a found name and sends it as a result.
func (s *scanState) report(ctx context.Context, name string, records []dns.Record) {
	cfg := s.cfg
	s.found.Add(1)
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
	// The list keeps the names the pass does not get to, for Stats.Pending,
	// and the ones still unanswered after it when something lists them.
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
				s.pending.add(rest)
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
	cfg, st := s.cfg, &s.stats
	if err := s.limiter.Wait(ctx); err != nil {
		s.pending.add(it)
		return
	}
	name := it.domain(&s.cfg)
	records, outcome := cfg.resolve(ctx, name, cfg.logf())
	if outcome = settle(ctx, outcome); outcome == dns.OutcomeCanceled {
		s.pending.add(it)
		return
	}
	st.retried.Add(1)
	if inconclusive(outcome) {
		if cfg.ListInconclusive {
			it.retried = true
			s.pending.add(it)
		}
		return
	}
	st.recovered.Add(1)
	st.counter(it.outcome).Add(-1)
	if outcome == dns.OutcomeFound && isWildcardAnswer(ctx, cfg, s.fp, name, records) {
		st.wildcardFiltered.Add(1)
		return
	}
	st.add(outcome)
	if outcome == dns.OutcomeFound {
		s.report(ctx, name, records)
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
