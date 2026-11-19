package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/permute"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// dryRunTarget is one target's -dry-run plan (#192).
type dryRunTarget struct {
	Domain     string `json:"domain"`
	Candidates int    `json:"candidates"` // names a scan would test
	Duplicates int    `json:"duplicates"` // wordlist duplicates removed
	Skipped    int    `json:"skipped"`    // invalid wordlist entries
	Excluded   int    `json:"excluded"`   // candidates out of scope under -exclude
	// Queries is one query per candidate and record type; QueriesMax also
	// counts every retry -attempts allows. Both respect -max-queries.
	Queries    int64 `json:"queries"`
	QueriesMax int64 `json:"queries_max"`
	// RateEffective is the query rate a scan is held to: -rate, or with a -r
	// pool -rate-per-resolver times the pool's size, whichever is lower; 0
	// when neither bounds it (#376).
	RateEffective int `json:"rate_effective,omitempty"`
	// Seconds and SecondsMax are the time those queries take at
	// RateEffective; 0 when it is unbounded.
	Seconds    float64 `json:"seconds,omitempty"`
	SecondsMax float64 `json:"seconds_max,omitempty"`
	// Preflight is the resolver's answer for the domain itself, as a scan's
	// preflight check gets it; empty in simulation mode.
	Preflight   string `json:"preflight,omitempty"`
	PreflightOK bool   `json:"preflight_ok"`
	// PoolPreflight is each -r pool member's answer to the same query
	// (#376). A failing member does not fail the dry run: a scan benches it
	// and carries on with the others.
	PoolPreflight []dryRunResolver `json:"pool_preflight,omitempty"`
	// OutOfScope is set for a target -exclude rules out: a scan refuses it,
	// so it has no candidates and gets no preflight query (#372).
	OutOfScope bool `json:"out_of_scope,omitempty"`
}

// dryRunResolver is one -r pool member's preflight answer (#376).
type dryRunResolver struct {
	Addr      string `json:"address"`
	Preflight string `json:"preflight"`
	OK        bool   `json:"ok"`
}

// preflightOK reports whether a preflight answer shows a working resolver.
func preflightOK(o dns.Outcome) bool {
	return o == dns.OutcomeFound || o == dns.OutcomeNXDomain
}

// dryRunRate returns the query rate a scan is held to and the flags that set
// it: -rate, or with a -r pool -rate-per-resolver times the pool's size,
// whichever is lower (#376). 0 means neither bounds it.
func dryRunRate(f cliFlags, pool *dns.Pool) (int, string) {
	rate, by := f.rate, fmt.Sprintf("-rate %d", f.rate)
	if pool != nil && f.ratePerRes > 0 {
		if poolRate := f.ratePerRes * pool.Size(); rate <= 0 || poolRate < rate {
			rate, by = poolRate, fmt.Sprintf("-rate-per-resolver %d x %d resolvers", f.ratePerRes, pool.Size())
		}
	}
	if rate <= 0 {
		return 0, ""
	}
	return rate, by
}

// dryRun prints what a scan would do without scanning: the candidates per
// target, query and duration estimates, and the resolver preflight, which is
// its only DNS traffic (#192). It fails only if a preflight fails.
func (s *session) dryRun() int {
	f := s.f
	timeout := time.Duration(f.timeoutMs) * time.Millisecond
	resolver := dns.NewResolver(timeout, f.dnsServer)
	defer dns.CloseIdleConnections(resolver)
	plans := make([]dryRunTarget, 0, len(s.targets))
	failed := false
	excluded := scan.Excluder(s.in.excludes)
	// The preflights are paced by -rate like a scan's queries (#372).
	ctx := dns.WithLimiter(context.Background(), dns.NewRateLimiter(f.rate))
	rate, rateBy := dryRunRate(f, s.in.pool)
	defer s.in.pool.CloseIdleConnections()
	for _, target := range s.targets {
		entries, duplicates, skipped := s.words.For(target)
		p := dryRunTarget{Domain: target, Duplicates: duplicates, Skipped: skipped, PreflightOK: true}
		if scan.TargetOutOfScope(s.in.excludes, target) {
			// A scan refuses it before any query, so the plan sends none.
			p.OutOfScope = true
			plans = append(plans, p)
			continue
		}
		for _, e := range entries {
			if len(s.in.excludes) > 0 && excluded(e+"."+target) {
				p.Excluded++
				continue
			}
			p.Candidates++
		}
		names := int64(p.Candidates)
		if f.maxQueries > 0 {
			names = min(names, int64(f.maxQueries))
		}
		// One lookup per name sends a query per type (#223, #249).
		p.Queries = names * int64(dns.QueriesFor(s.in.recordTypes))
		p.QueriesMax = p.Queries * int64(max(s.in.maxAttempts, 1))
		p.RateEffective = rate
		if rate > 0 {
			p.Seconds = float64(p.Queries) / float64(rate)
			p.SecondsMax = float64(p.QueriesMax) / float64(rate)
		}
		if !f.testMode {
			lookup := dns.Lookup{Resolver: resolver, Timeout: timeout, Attempts: s.in.maxAttempts, Types: s.in.recordTypes}
			_, outcome := lookup.Resolve(ctx, target)
			p.Preflight = outcome.String()
			p.PreflightOK = preflightOK(outcome)
			failed = failed || !p.PreflightOK
			if s.in.pool != nil {
				for _, r := range s.in.pool.Probe(ctx, lookup, target, f.concurrency) {
					p.PoolPreflight = append(p.PoolPreflight, dryRunResolver{Addr: r.Addr, Preflight: r.Outcome.String(), OK: preflightOK(r.Outcome)})
				}
			}
		}
		plans = append(plans, p)
	}

	switch s.format {
	case output.FormatJSON, output.FormatJSONL:
		enc := json.NewEncoder(s.a.stdout)
		if s.format == output.FormatJSON {
			enc.SetIndent("", "  ")
			if err := enc.Encode(plans); err != nil {
				s.out.Error("writing dry run: %v", err)
				return exitFailure
			}
			break
		}
		for _, p := range plans {
			if err := enc.Encode(p); err != nil {
				s.out.Error("writing dry run: %v", err)
				return exitFailure
			}
		}
	default:
		s.printDryRun(plans, rateBy)
	}
	if notes := dryRunNotes(f, s.in.sources, s.deepWords); len(notes) > 0 {
		s.out.Info("Not included in the estimate: %s", strings.Join(notes, "; "))
	}
	if failed {
		return exitFailure
	}
	return exitOK
}

// printDryRun writes the plan as text; rateBy names the flags that bound
// the duration.
func (s *session) printDryRun(plans []dryRunTarget, rateBy string) {
	w := s.a.stdout
	for _, p := range plans {
		_, _ = fmt.Fprintf(w, "%s\n", p.Domain)
		if p.OutOfScope {
			_, _ = fmt.Fprintf(w, "  out of scope under -exclude: not scanned, no queries\n")
			continue
		}
		_, _ = fmt.Fprintf(w, "  candidates  %d (%d duplicates removed, %d invalid skipped, %d excluded)\n", p.Candidates, p.Duplicates, p.Skipped, p.Excluded)
		_, _ = fmt.Fprintf(w, "  queries     %d (up to %d with retries)\n", p.Queries, p.QueriesMax)
		if p.Seconds > 0 {
			_, _ = fmt.Fprintf(w, "  duration    %s (up to %s) at %d/s (%s)\n", dryRunDuration(p.Seconds), dryRunDuration(p.SecondsMax), p.RateEffective, rateBy)
		} else {
			_, _ = fmt.Fprintf(w, "  duration    not bounded by -rate (unlimited)\n")
		}
		if p.Preflight != "" {
			_, _ = fmt.Fprintf(w, "  preflight   %s via %s: %s\n", dryRunStatus(p.PreflightOK), dns.DisplayServer(s.f.dnsServer), p.Preflight)
		}
		for _, r := range p.PoolPreflight {
			_, _ = fmt.Fprintf(w, "  pool        %s via %s: %s\n", dryRunStatus(r.OK), r.Addr, r.Preflight)
		}
	}
}

// dryRunStatus labels a preflight answer.
func dryRunStatus(ok bool) string {
	if ok {
		return "ok"
	}
	return "FAILED"
}

// dryRunDuration rounds an estimate for display.
func dryRunDuration(seconds float64) string {
	return time.Duration(seconds * float64(time.Second)).Round(time.Second).String()
}

// dryRunNotes names the work a scan may add that a dry run cannot count
// without sending queries. deep is the -recursive-w list, if any.
func dryRunNotes(f cliFlags, sources []string, deep *wordlist.Prepared) []string {
	var notes []string
	for _, src := range sources {
		notes = append(notes, fmt.Sprintf("%s names (fetched at scan time)", passive.Labels[src]))
	}
	if f.axfr {
		notes = append(notes, "-axfr names (a zone transfer from each name server at scan time)")
	}
	if f.permute || f.seedsFile != "" {
		notes = append(notes, fmt.Sprintf("the -permute pass (built from what the scan finds: up to %d candidates per name, at most %d per target)", permute.PerSeed, candidates.MaxPermutations))
	}
	if f.recursive && f.depth > 1 {
		// What each found name costs is known; how many are found is not.
		if deep != nil {
			entries, _, _ := deep.For("")
			notes = append(notes, fmt.Sprintf("-recursive levels (built from what the scan finds: %d -recursive-w candidates under each name found)", len(entries)))
		} else {
			notes = append(notes, "-recursive levels (built from what the scan finds: the -w candidates again under each name found)")
		}
	}
	if f.followRecs {
		notes = append(notes, "-follow-records targets (named by the records of what the scan finds)")
	}
	if !f.testMode {
		notes = append(notes, "wildcard probes")
	}
	return notes
}
