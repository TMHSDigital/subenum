// Package subenum embeds subenum's subdomain enumeration engine in other Go
// programs. It is the same engine the command-line tool runs: a worker pool
// over a wordlist, wildcard fingerprinting and filtering, per-second query
// pacing, retries, a reliability guard and per-outcome accounting.
//
// Scan is the simplest entry point and returns everything a finished scan
// found. Run streams results, notices and progress as they happen.
//
// Only enumerate domains you own or have permission to test. Simulate
// produces synthetic results without sending any DNS queries, which is what
// examples and tests should use.
//
// This package follows semantic versioning from v1.0.0. Until then it may
// change between minor releases; the command-line interface is stable.
package subenum

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TMHSDigital/subenum/data"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/validate"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// Defaults applied to a Config's zero values. They are the command line's
// defaults too; TestDefaultsMatchTheCLI keeps them in step.
const (
	DefaultResolver    = "8.8.8.8:53"
	DefaultConcurrency = 100
	DefaultTimeout     = time.Second
	DefaultAttempts    = 1
	DefaultHitRate     = 15
)

// Config describes one scan. Every zero value selects the default above, so
// Config{Domain: "example.com"} is a complete configuration.
type Config struct {
	// Domain is the apex to enumerate under, for example "example.com". A
	// URL, a trailing dot, a port or an internationalized name are
	// normalized the way the command line normalizes them.
	Domain string

	// Words are the subdomain labels to try, one label per entry ("www"),
	// or a dotted path to enumerate deeper ("api.eu"). Blank entries, "#"
	// comments, duplicates and entries too long to form a legal name are
	// dropped. Nil uses DefaultWords.
	Words []string

	// Resolver is the DNS server every lookup goes to: "ip:port",
	// "tls://host[:853]" for DNS over TLS, or "https://host/path" for DNS
	// over HTTPS. Empty means DefaultResolver.
	Resolver string

	// ResolverPool spreads candidate lookups over several plain-UDP
	// resolvers ("ip" or "ip:port"), which is faster but less trustworthy
	// than one server. Every name a pool member reports is re-checked
	// against Resolver, and only Resolver's answer is reported. Preflight
	// and wildcard probes always use Resolver.
	ResolverPool []string

	// Concurrency is the number of workers looking up names at once.
	Concurrency int

	// Timeout bounds one lookup of one record type.
	Timeout time.Duration

	// Attempts is the number of tries per name. 1 does not retry. Only
	// failures (timeouts, SERVFAIL, REFUSED) are retried, never an answer
	// saying the name does not exist.
	Attempts int

	// Rate caps DNS queries per second on the wire across all workers,
	// counting every record type, retry and wildcard probe. 0 is
	// unlimited. Pace scans of resolvers you do not own.
	Rate int

	// Types are the record types to look up: "A", "AAAA" and "CNAME". Nil
	// looks up A and AAAA. CNAME is what populates Result.Takeover.
	Types []string

	// Recursive enumerates Words again under every name that is found,
	// down to Depth levels.
	Recursive bool

	// Depth is the deepest level a recursive scan reaches. 1, the default,
	// does not recurse. Each level multiplies the candidate count by
	// len(Words), so set MaxQueries as well.
	Depth int

	// MaxQueries caps how many candidate names are tested. 0 is unlimited.
	MaxQueries int

	// Exclude lists names that are out of scope and are never queried.
	// "mail.example.com" excludes one name; "*.corp.example.com" excludes
	// a whole branch.
	Exclude []string

	// Force scans a domain whose DNS answers every name (a wildcard zone)
	// instead of refusing. Results matching the wildcard fingerprint are
	// still dropped and counted in Stats.WildcardFiltered.
	Force bool

	// NoAbort keeps scanning when more than a fifth of lookups fail.
	// Without it the scan stops early and Stats.Aborted is set, because a
	// resolver that is failing cannot be distinguished from a domain whose
	// names do not exist.
	NoAbort bool

	// Simulate invents results instead of sending DNS queries, for demos,
	// examples and tests. HitRate and Seed apply only to simulated scans.
	Simulate bool

	// HitRate is the percentage of names a simulated scan reports as
	// resolved, 1 to 100.
	HitRate int

	// Seed makes a simulated scan reproducible: the same seed and words
	// give the same results. 0 picks a random seed.
	Seed uint64

	// Verbose logs every lookup through Logf.
	Verbose bool

	// Logf receives verbose lines when Verbose is set. Nil writes them to
	// standard error.
	Logf func(format string, args ...any)
}

// Record is one DNS record behind a result.
type Record struct {
	Type  string // "A", "AAAA" or "CNAME"
	Value string // an address, or the target of a CNAME
}

// Result is a subdomain that resolved.
type Result struct {
	// Name is the full subdomain, such as "www.example.com".
	Name string

	// Records are the records it resolved to. A result found through a
	// CNAME carries the alias and the addresses it leads to.
	Records []Record

	// Takeover is a hint that a CNAME points somewhere unclaimed:
	// "dangling" (the target does not resolve), "provider:<name>" (the
	// target belongs to a known hosting provider) or "dangling:<name>"
	// (both). It is derived only from DNS, so it is a lead to verify by
	// hand, not a finding. Empty unless Types includes "CNAME".
	Takeover string
}

// Stats accounts for every candidate name a finished scan looked up.
type Stats struct {
	// Outcomes. Each candidate name lands in exactly one of these.
	Found            int64 // resolved and reported
	NXDomain         int64 // the resolver said the name does not exist
	Timeout          int64 // no answer in time
	Refused          int64 // the resolver refused to answer
	Other            int64 // any other failure, such as SERVFAIL
	WildcardFiltered int64 // resolved, but matched the wildcard fingerprint

	QueriesSent int64 // DNS queries sent, retries included; 0 when simulated
	Skipped     int64 // candidates left untested because MaxQueries was reached
	Excluded    int64 // candidates left untested because Exclude covered them
	Takeover    int64 // results carrying a Takeover hint

	PoolHits    int64 // names a ResolverPool member reported
	Confirmed   int64 // of those, the ones Resolver confirmed
	Unconfirmed int64 // of those, the ones Resolver said do not exist

	// Aborted reports that the reliability guard stopped the scan early,
	// so the results are incomplete and the negatives mean nothing.
	Aborted bool

	// Wildcard reports that the domain answers every name. Only Force
	// lets such a scan run.
	Wildcard bool

	// WildcardFingerprint is the answer the wildcard gives, learned from
	// random probes. Empty when there is no wildcard.
	WildcardFingerprint []Record
}

// Total returns the number of candidate names that were looked up and
// classified.
func (s Stats) Total() int64 {
	return s.Found + s.NXDomain + s.Timeout + s.Refused + s.Other + s.WildcardFiltered
}

// Kind says which fields of an Event are set.
type Kind int

// Event kinds.
const (
	// KindResult reports one resolved subdomain in Event.Result.
	KindResult Kind = iota
	// KindProgress reports how far the scan has got, in Event.Processed,
	// Event.Total and Event.Found.
	KindProgress
	// KindNotice reports something worth telling the user, in
	// Event.Message, categorized by Event.Notice.
	KindNotice
	// KindError reports in Event.Message a problem serious enough to stop
	// the scan: the domain is out of scope, the resolver failed a
	// preflight check, the domain is a wildcard zone and Force is not
	// set, or the reliability guard gave up. Few or no results follow.
	KindError
	// KindDone is always the last event, and reports Event.Stats. It
	// arrives whether the scan completed, never started, was stopped by
	// the reliability guard or was cancelled through the context.
	KindDone
)

// String names a kind.
func (k Kind) String() string {
	switch k {
	case KindResult:
		return "result"
	case KindProgress:
		return "progress"
	case KindNotice:
		return "notice"
	case KindError:
		return "error"
	case KindDone:
		return "done"
	}
	return "unknown"
}

// Notice categorizes a KindNotice event, so a consumer can act on it without
// reading the message.
type Notice int

// Notice categories.
const (
	// NoticeNone is the zero value, used by events that are not notices.
	NoticeNone Notice = iota
	// NoticeWildcard means the domain answers every name, or that the
	// wildcard check itself failed under Force.
	NoticeWildcard
	// NoticeCap means MaxQueries was reached and candidates were skipped.
	NoticeCap
	// NoticeCeiling means a recursive scan could generate a very large
	// number of queries.
	NoticeCeiling
	// NoticeSkip means one recursive branch was not expanded.
	NoticeSkip
)

// String names a notice category.
func (n Notice) String() string {
	switch n {
	case NoticeWildcard:
		return "wildcard"
	case NoticeCap:
		return "cap"
	case NoticeCeiling:
		return "ceiling"
	case NoticeSkip:
		return "skip"
	}
	return "none"
}

// Event is one update from a running scan.
type Event struct {
	Kind Kind

	// Result is the subdomain found, on KindResult.
	Result Result

	// Notice categorizes a KindNotice event.
	Notice Notice

	// Message is the human-readable text of a KindNotice or KindError
	// event.
	Message string

	// Processed, Total and Found report progress on KindProgress. Total
	// grows during a recursive scan as new branches are queued, so treat
	// it as an estimate.
	Processed int64
	Total     int64
	Found     int64

	// Stats is the final accounting, on KindDone.
	Stats Stats

	// Stopped is set on KindDone when the scan ended before testing any
	// candidate, after a KindError (the domain is out of scope, a wildcard
	// zone without Force, a failed resolver check) or because ctx was
	// cancelled during those checks. Stats then covers only the checks.
	Stopped bool
}

// DefaultWords returns the bundled wordlist: the most common subdomain labels,
// from SecLists' top-5000 list, already normalized and deduplicated.
// Config.Words defaults to it. The returned slice is a fresh copy, safe to
// append to or filter.
func DefaultWords() []string {
	return slices.Clone(defaultWords())
}

// defaultWords parses the bundled list once; callers must not modify it.
var defaultWords = sync.OnceValue(func() []string {
	lines, err := wordlist.ReadLinesFrom(strings.NewReader(data.Subdomains5k))
	if err != nil {
		// The list is compiled into the binary, so this cannot fail.
		panic("subenum: reading the bundled wordlist: " + err.Error())
	}
	words, _, _ := wordlist.Build(lines, "")
	return words
})

// doneGrace is how long Run's forwarder waits to hand over the final event
// after ctx is cancelled, when the caller may have stopped reading.
var doneGrace atomic.Int64 // a time.Duration; atomic so tests can change it while forwarders run

func init() { doneGrace.Store(int64(time.Second)) }

// ErrNoWords is returned when a Config's wordlist has no usable entries.
var ErrNoWords = errors.New("subenum: wordlist has no usable entries")

// Run starts a scan and streams its events. The channel ends with exactly one
// KindDone event and is then closed, so a range loop over it always sees the
// final Stats. Problems with cfg itself are reported before the scan starts,
// as an error and no channel.
//
// Read the channel until it closes, or cancel ctx: the usual
// `for ev := range events { ... break ... }` with a deferred cancel is safe.
// While ctx is live, an unread channel pauses the scan once its buffer
// fills. Once ctx is cancelled the scan stops and never waits for the
// caller: results nobody reads may be dropped, and a caller that keeps
// reading still gets KindDone with the counts so far. Every goroutine the
// scan started exits within about a second of cancellation, whether or not
// the channel is read (#112).
func Run(ctx context.Context, cfg Config) (<-chan Event, error) {
	internal, err := cfg.options()
	if err != nil {
		return nil, err
	}
	in := make(chan scan.Event, 64)
	go scan.Run(ctx, internal.Config(), in)

	out := make(chan Event, 64)
	go func() {
		defer close(out)
		// scan.Run always ends with exactly one EventDone (#99), so the
		// channel ends with exactly one KindDone too.
		for ev := range in {
			forward(ctx, out, translate(ev))
		}
	}()
	return out, nil
}

// forward hands ev to the caller. Before cancellation it waits for the
// caller to read. After it, it never blocks the engine, which must be
// drained to finish: other events are dropped when the buffer is full, and
// the final event waits at most doneGrace for a reader.
func forward(ctx context.Context, out chan<- Event, ev Event) {
	if ctx.Err() == nil {
		select {
		case out <- ev:
			return
		case <-ctx.Done():
		}
	}
	if ev.Kind != KindDone {
		select {
		case out <- ev:
		default:
		}
		return
	}
	timer := time.NewTimer(time.Duration(doneGrace.Load()))
	defer timer.Stop()
	select {
	case out <- ev:
	case <-timer.C:
	}
}

// Scan runs a scan to completion and returns everything it found, in the
// order the names resolved.
//
// An error means the results are incomplete or absent: the context was
// cancelled, the domain is a wildcard zone and Force is not set, the resolver
// failed its preflight check, or too many lookups were failing and the
// reliability guard stopped the scan. The results and Stats gathered up to
// that point come back alongside it, so a partial scan can still be reported.
func Scan(ctx context.Context, cfg Config) ([]Result, Stats, error) {
	events, err := Run(ctx, cfg)
	if err != nil {
		return nil, Stats{}, err
	}
	var results []Result
	var stats Stats
	var failure string
	for ev := range events {
		switch ev.Kind {
		case KindResult:
			results = append(results, ev.Result)
		case KindError:
			if failure == "" {
				failure = ev.Message
			}
		case KindDone:
			stats = ev.Stats
		}
	}
	switch {
	case ctx.Err() != nil:
		return results, stats, ctx.Err()
	case failure != "":
		// The engine's wording names the specific problem.
		return results, stats, fmt.Errorf("subenum: scanning %s: %s", cfg.Domain, failure)
	case stats.Aborted:
		return results, stats, fmt.Errorf("subenum: scanning %s: stopped early, too many lookups were failing", cfg.Domain)
	}
	return results, stats, nil
}

// options validates the config, applies defaults and builds the internal
// options. Messages name Config fields, since a library caller has no flags.
func (c Config) options() (scan.Options, error) {
	domain, _, err := validate.NormalizeDomain(c.Domain)
	if err != nil {
		return scan.Options{}, fmt.Errorf("subenum: Domain: %w", err)
	}

	switch {
	case c.Concurrency < 0:
		return scan.Options{}, fmt.Errorf("subenum: Concurrency must not be negative, got %d", c.Concurrency)
	case c.Timeout < 0:
		return scan.Options{}, fmt.Errorf("subenum: Timeout must not be negative, got %s", c.Timeout)
	case c.Attempts < 0:
		return scan.Options{}, fmt.Errorf("subenum: Attempts must not be negative, got %d", c.Attempts)
	case c.Rate < 0:
		return scan.Options{}, fmt.Errorf("subenum: Rate must be 0 (unlimited) or positive, got %d", c.Rate)
	case c.MaxQueries < 0:
		return scan.Options{}, fmt.Errorf("subenum: MaxQueries must be 0 (unlimited) or positive, got %d", c.MaxQueries)
	case c.Depth < 0:
		return scan.Options{}, fmt.Errorf("subenum: Depth must not be negative, got %d", c.Depth)
	case c.Simulate && c.HitRate != 0 && (c.HitRate < 1 || c.HitRate > 100):
		return scan.Options{}, fmt.Errorf("subenum: HitRate must be 1-100, got %d", c.HitRate)
	}

	resolver := orDefaultString(c.Resolver, DefaultResolver)
	if !c.Simulate {
		if err := validate.DNSServer(resolver); err != nil {
			return scan.Options{}, fmt.Errorf("subenum: Resolver %s: %w", resolver, err)
		}
	}

	types, err := parseTypes(c.Types)
	if err != nil {
		return scan.Options{}, err
	}

	words := c.Words
	if words == nil {
		words = DefaultWords()
	}
	entries, _, _ := wordlist.Build(words, domain)
	if len(entries) == 0 {
		return scan.Options{}, ErrNoWords
	}

	opts := scan.Options{
		Domain:      domain,
		Entries:     entries,
		Concurrency: orDefault(c.Concurrency, DefaultConcurrency),
		TimeoutMs:   ceilMillis(orDefaultDuration(c.Timeout, DefaultTimeout)),
		DNSServer:   resolver,
		Simulate:    c.Simulate,
		HitRate:     orDefault(c.HitRate, DefaultHitRate),
		Seed:        c.Seed,
		Attempts:    orDefault(c.Attempts, DefaultAttempts),
		Force:       c.Force,
		Types:       types,
		Recursive:   c.Recursive,
		Depth:       orDefault(c.Depth, 1),
		Rate:        c.Rate,
		MaxQueries:  c.MaxQueries,
		Exclude:     c.Exclude,
		NoAbort:     c.NoAbort,
		Verbose:     c.Verbose,
		Logf:        dns.Logf(c.Logf),
	}

	if len(c.ResolverPool) > 0 {
		if c.Simulate {
			return scan.Options{}, errors.New("subenum: ResolverPool cannot be used with Simulate, which sends no DNS queries")
		}
		addrs, err := dns.ParseResolverList(c.ResolverPool)
		if err != nil {
			return scan.Options{}, fmt.Errorf("subenum: ResolverPool: %w", err)
		}
		if len(addrs) == 0 {
			return scan.Options{}, errors.New("subenum: ResolverPool lists no resolvers")
		}
		opts.Pool = dns.NewPool(addrs, time.Duration(opts.TimeoutMs)*time.Millisecond)
	}

	if err := opts.Validate(); err != nil {
		return scan.Options{}, fmt.Errorf("subenum: %s", fieldNames(err.Error()))
	}
	return opts, nil
}

// parseTypes checks the record types, defaulting to A and AAAA.
func parseTypes(types []string) ([]string, error) {
	if len(types) == 0 {
		return nil, nil
	}
	parsed, err := dns.ParseTypes(strings.Join(types, ","))
	if err != nil {
		return nil, fmt.Errorf("subenum: Types: %w", err)
	}
	return parsed, nil
}

// ceilMillis rounds a duration up to whole milliseconds, the engine's unit,
// so a positive Timeout below 1ms becomes 1ms instead of an invalid 0.
func ceilMillis(d time.Duration) int {
	return int((d + time.Millisecond - 1) / time.Millisecond)
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func orDefaultString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDefaultDuration(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}

// configFields names each engine setting as the Config field that sets it.
// Engine messages refer to settings by token (#100), and a library caller
// has no flags: "Use {force} to scan anyway" reads "Use Force to scan anyway".
var configFields = map[scan.Setting]string{
	scan.SettingConcurrency: "Concurrency",
	scan.SettingTimeout:     "Timeout",
	scan.SettingAttempts:    "Attempts",
	scan.SettingHitRate:     "HitRate",
	scan.SettingDepth:       "Depth",
	scan.SettingRate:        "Rate",
	scan.SettingMaxQueries:  "MaxQueries",
	scan.SettingExclude:     "Exclude",
	scan.SettingRecursive:   "Recursive",
	scan.SettingForce:       "Force",
}

// fieldNames renders the setting tokens in an engine message as Config
// fields.
func fieldNames(msg string) string {
	return scan.Render(msg, func(st scan.Setting) string { return configFields[st] })
}

// translate converts an internal event to the public one.
func translate(ev scan.Event) Event {
	out := Event{
		Message:   fieldNames(ev.Message),
		Processed: ev.Processed,
		Total:     ev.Total,
		Found:     ev.Found,
	}
	switch ev.Kind {
	case scan.EventResult:
		out.Kind = KindResult
		out.Result = Result{Name: ev.Domain, Records: records(ev.Records), Takeover: ev.Takeover}
	case scan.EventProgress:
		out.Kind = KindProgress
	case scan.EventNotice:
		out.Kind = KindNotice
		out.Notice = notice(ev.Notice)
	case scan.EventError:
		out.Kind = KindError
	case scan.EventDone:
		out.Kind = KindDone
		out.Stats = stats(ev.Stats)
		out.Stopped = ev.Stopped
	}
	return out
}

func records(in []dns.Record) []Record {
	if len(in) == 0 {
		return nil
	}
	out := make([]Record, 0, len(in))
	for _, r := range in {
		out = append(out, Record{Type: r.Type, Value: r.Value})
	}
	return out
}

func notice(n scan.NoticeKind) Notice {
	switch n {
	case scan.NoticeWildcard:
		return NoticeWildcard
	case scan.NoticeCap:
		return NoticeCap
	case scan.NoticeCeiling:
		return NoticeCeiling
	case scan.NoticeSkip:
		return NoticeSkip
	}
	return NoticeNone
}

func stats(s scan.Stats) Stats {
	return Stats{
		Found:            s.Found,
		NXDomain:         s.NXDomain,
		Timeout:          s.Timeout,
		Refused:          s.Refused,
		Other:            s.Other,
		WildcardFiltered: s.WildcardFiltered,

		QueriesSent: s.QueriesSent,
		Skipped:     s.Skipped,
		Excluded:    s.Excluded,
		Takeover:    s.Takeover,

		PoolHits:    s.PoolHits,
		Confirmed:   s.Confirmed,
		Unconfirmed: s.Unconfirmed,

		Aborted:             s.Aborted,
		Wildcard:            s.Wildcard,
		WildcardFingerprint: records(s.Fingerprint),
	}
}
