package main

import (
	"fmt"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// buildSummary assembles the run-quality report (#70) from each target's
// status and result. The overall verdict is the worst target verdict.
func buildSummary(f cliFlags, targets, status []string, results []targetResult, started time.Time, elapsed time.Duration) output.Summary {
	s := output.Summary{
		Type:       "summary",
		Schema:     output.SummarySchema,
		Tool:       ProgramName,
		Version:    resolveVersion(),
		Started:    started.UTC().Truncate(time.Millisecond),
		DurationMs: elapsed.Milliseconds(),
		Simulated:  f.testMode,
		RateLimit:  f.rate,
		Verdict:    scan.VerdictComplete,
		Targets:    make([]output.TargetSummary, 0, len(targets)),
	}
	if f.testMode {
		s.Seed = f.seed
	} else {
		s.Resolver = f.dnsServer
		s.Transport = dns.Transport(f.dnsServer)
		s.Zone = f.simZone
	}

	worst := -1
	for i, domain := range targets {
		t := targetSummary(domain, status[i], results[i])
		s.QueriesSent += t.QueriesSent
		if worst < 0 || scan.VerdictRank(t.Verdict) > scan.VerdictRank(s.Targets[worst].Verdict) {
			worst = i
		}
		s.Targets = append(s.Targets, t)
	}
	if worst >= 0 {
		w := s.Targets[worst]
		s.Verdict, s.Reason = w.Verdict, w.Reason
		if len(targets) > 1 {
			s.Reason = w.Domain + ": " + w.Reason
		}
	}
	if f.pool != nil {
		s.Resolvers = f.pool.Stats()
	}
	if secs := elapsed.Seconds(); secs > 0 {
		s.AchievedQPS = float64(int(float64(s.QueriesSent)/secs*10)) / 10
	}
	return s
}

func targetSummary(domain, status string, res targetResult) output.TargetSummary {
	t := output.TargetSummary{Domain: domain, Status: status, Error: res.err}
	switch {
	case status == "" || status == "skipped":
		if t.Status == "" {
			t.Status = "not_run"
		}
		t.Verdict, t.Reason = scan.VerdictUnreliable, "not scanned"
		if status == "skipped" {
			t.Reason = "not scanned: an earlier target's resolver looked overloaded"
		}
		return t
	case !res.done:
		reason := res.err
		if reason == "" {
			reason = "the scan did not run to completion"
		}
		t.Verdict, t.Reason = scan.VerdictUnreliable, reason
		return t
	}
	ev := res.final
	st := ev.Stats
	t.Processed, t.Total, t.Found = ev.Processed, ev.Total, ev.Found
	t.Outcomes = output.Outcomes{
		Resolved:         st.Found,
		NXDomain:         st.NXDomain,
		Timeout:          st.Timeout,
		Refused:          st.Refused,
		Other:            st.Other,
		WildcardFiltered: st.WildcardFiltered,
		Excluded:         st.Excluded,
	}
	t.QueriesSent = st.QueriesSent
	t.SkippedCap = st.Skipped
	t.Takeover = st.Takeover
	if p := res.permutation; p != nil {
		t.Permutation = &output.PermutationSummary{Seeds: p.seeds, Candidates: p.candidates, Found: p.found}
		if p.pass.done {
			t.Permutation.Verdict, _ = p.pass.final.Stats.Verdict(status == "interrupted")
		}
	}
	t.PoolHits, t.Confirmed, t.Unconfirmed = st.PoolHits, st.Confirmed, st.Unconfirmed
	t.Wildcard = st.Wildcard
	if st.Wildcard {
		t.Fingerprint = st.Fingerprint
	}
	t.Verdict, t.Reason = st.Verdict(status == "interrupted")
	if st.Wildcard && t.Verdict == scan.VerdictComplete {
		t.Reason += fmt.Sprintf("; wildcard zone, %d answers filtered by fingerprint", st.WildcardFiltered)
	}
	return t
}
