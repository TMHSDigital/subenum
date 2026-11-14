package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/scan"
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
	// Seconds and SecondsMax are the time those queries take at -rate; 0
	// when -rate is unlimited.
	Seconds    float64 `json:"seconds,omitempty"`
	SecondsMax float64 `json:"seconds_max,omitempty"`
	// Preflight is the resolver's answer for the domain itself, as a scan's
	// preflight check gets it; empty in simulation mode.
	Preflight   string `json:"preflight,omitempty"`
	PreflightOK bool   `json:"preflight_ok"`
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
	for _, target := range s.targets {
		entries, duplicates, skipped := s.words.For(target)
		p := dryRunTarget{Domain: target, Duplicates: duplicates, Skipped: skipped, PreflightOK: true}
		for _, e := range entries {
			if len(s.in.excludes) > 0 && scan.IsExcluded(s.in.excludes, e+"."+target) {
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
		if f.rate > 0 {
			p.Seconds = float64(p.Queries) / float64(f.rate)
			p.SecondsMax = float64(p.QueriesMax) / float64(f.rate)
		}
		if !f.testMode {
			lookup := dns.Lookup{Resolver: resolver, Timeout: timeout, Attempts: s.in.maxAttempts, Types: s.in.recordTypes}
			_, outcome := lookup.Resolve(context.Background(), target)
			p.Preflight = outcome.String()
			p.PreflightOK = outcome == dns.OutcomeFound || outcome == dns.OutcomeNXDomain
			failed = failed || !p.PreflightOK
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
		s.printDryRun(plans)
	}
	if notes := dryRunNotes(f, s.in.sources); len(notes) > 0 {
		s.out.Info("Not included in the estimate: %s", strings.Join(notes, "; "))
	}
	if failed {
		return exitFailure
	}
	return exitOK
}

// printDryRun writes the plan as text.
func (s *session) printDryRun(plans []dryRunTarget) {
	w := s.a.stdout
	for _, p := range plans {
		_, _ = fmt.Fprintf(w, "%s\n", p.Domain)
		_, _ = fmt.Fprintf(w, "  candidates  %d (%d duplicates removed, %d invalid skipped, %d excluded)\n", p.Candidates, p.Duplicates, p.Skipped, p.Excluded)
		_, _ = fmt.Fprintf(w, "  queries     %d (up to %d with retries)\n", p.Queries, p.QueriesMax)
		if p.Seconds > 0 {
			_, _ = fmt.Fprintf(w, "  duration    %s (up to %s) at -rate %d\n", dryRunDuration(p.Seconds), dryRunDuration(p.SecondsMax), s.f.rate)
		} else {
			_, _ = fmt.Fprintf(w, "  duration    not bounded by -rate (unlimited)\n")
		}
		if p.Preflight != "" {
			status := "ok"
			if !p.PreflightOK {
				status = "FAILED"
			}
			_, _ = fmt.Fprintf(w, "  preflight   %s via %s: %s\n", status, s.f.dnsServer, p.Preflight)
		}
	}
}

// dryRunDuration rounds an estimate for display.
func dryRunDuration(seconds float64) string {
	return time.Duration(seconds * float64(time.Second)).Round(time.Second).String()
}

// dryRunNotes names the work a scan may add that a dry run cannot count
// without sending queries.
func dryRunNotes(f cliFlags, sources []string) []string {
	var notes []string
	for _, src := range sources {
		notes = append(notes, fmt.Sprintf("%s names (fetched at scan time)", passive.Labels[src]))
	}
	if f.axfr {
		notes = append(notes, "-axfr names (a zone transfer from each name server at scan time)")
	}
	if f.permute || f.seedsFile != "" {
		notes = append(notes, "the -permute pass (built from what the scan finds)")
	}
	if f.recursive {
		notes = append(notes, "-recursive levels (built from what the scan finds)")
	}
	if !f.testMode {
		notes = append(notes, "wildcard probes")
	}
	return notes
}
