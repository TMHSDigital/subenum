// Package report builds the run-quality report (#70) from finished scans.
// The CLI and the TUI share it, so a -format jsonl file ends with the same
// summary line whichever front end wrote it (#118).
package report

import (
	"fmt"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// Run describes a run for New.
type Run struct {
	Version   string // the tool version
	Started   time.Time
	Simulated bool
	Seed      uint64 // reported for simulated runs
	Resolver  string // -dns-server, reported for real runs
	Zone      string // -simulate-zone, if any
	RateLimit int
}

// New starts a summary for a run; add targets with Finish.
func New(r Run) output.Summary {
	s := output.Summary{
		Type:      "summary",
		Schema:    output.SummarySchema,
		Tool:      "subenum",
		Version:   r.Version,
		Started:   r.Started.UTC().Truncate(time.Millisecond),
		Simulated: r.Simulated,
		RateLimit: r.RateLimit,
		Verdict:   scan.VerdictComplete,
	}
	if r.Simulated {
		s.Seed = r.Seed
	} else {
		s.Resolver = r.Resolver
		s.Transport = dns.Transport(r.Resolver)
		s.Zone = r.Zone
	}
	return s
}

// Target summarizes one domain's scan. status is "ok", "failed",
// "interrupted", "skipped" or "" (never run); done reports whether the scan
// sent its final event, final.
func Target(domain, status, errMsg string, done bool, final scan.Event) output.TargetSummary {
	t := output.TargetSummary{Domain: domain, Status: status, Error: errMsg}
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
	case !done:
		reason := errMsg
		if reason == "" {
			reason = "the scan did not run to completion"
		}
		t.Verdict, t.Reason = scan.VerdictUnreliable, reason
		return t
	}
	st := final.Stats
	t.Processed, t.Total, t.Found = final.Processed, final.Total, final.Found
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

// Finish adds the targets to s, sets the overall verdict (the worst
// target's) and the achieved query rate over elapsed.
func Finish(s *output.Summary, targets []output.TargetSummary, elapsed time.Duration) {
	s.DurationMs = elapsed.Milliseconds()
	s.Targets = make([]output.TargetSummary, 0, len(targets))
	worst := -1
	for i, t := range targets {
		s.QueriesSent += t.QueriesSent
		if worst < 0 || scan.VerdictRank(t.Verdict) > scan.VerdictRank(targets[worst].Verdict) {
			worst = i
		}
		s.Targets = append(s.Targets, t)
	}
	if worst >= 0 {
		w := targets[worst]
		s.Verdict, s.Reason = w.Verdict, w.Reason
		if len(targets) > 1 {
			s.Reason = w.Domain + ": " + w.Reason
		}
	}
	if secs := elapsed.Seconds(); secs > 0 {
		s.AchievedQPS = float64(int(float64(s.QueriesSent)/secs*10)) / 10
	}
}
