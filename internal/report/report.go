// Package report builds the run-quality report (#70) from finished scans.
// The CLI and the TUI share it, so a -format jsonl file ends with the same
// summary line whichever front end wrote it (#118).
package report

import (
	"fmt"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
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

// Status is how a target's scan ended (#331). The zero value is a target
// that never ran.
type Status string

// The target statuses.
const (
	StatusNotRun      Status = ""
	StatusOK          Status = "ok"
	StatusFailed      Status = "failed"
	StatusInterrupted Status = "interrupted"
	// StatusSkipped is a target left out after an earlier target's
	// reliability abort.
	StatusSkipped Status = "skipped"
)

// Label is the status as the terminal's Targets table shows it.
func (s Status) Label() string {
	if s == StatusNotRun {
		return "not run"
	}
	return string(s)
}

// Value is the status as the report's status field writes it
// (output.TargetSummary.Status).
func (s Status) Value() string {
	if s == StatusNotRun {
		return "not_run"
	}
	return string(s)
}

// Target summarizes one domain's scan. done reports whether the scan
// finished, with final as its last event. name renders the settings the
// verdict reason refers to, in the caller's terms (#100).
func Target(domain string, status Status, errMsg string, done bool, final scan.Event, name func(scan.Setting) string) output.TargetSummary {
	t := target(domain, status, errMsg, done, final)
	t.Reason = scan.Render(t.Reason, name)
	return t
}

func target(domain string, status Status, errMsg string, done bool, final scan.Event) output.TargetSummary {
	t := output.TargetSummary{Domain: domain, Status: status.Value(), Error: errMsg}
	switch {
	case status == StatusNotRun || status == StatusSkipped:
		t.Verdict, t.Reason = scan.VerdictUnreliable, "not scanned"
		if status == StatusSkipped {
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
	switch {
	case st.Skipped > 0 && st.Expired:
		t.StoppedBy = "duration"
	case st.Skipped > 0:
		t.StoppedBy = "queries"
	}
	t.Takeover = st.Takeover
	t.ParentChecks, t.ParentQueries = st.ParentChecks, st.ParentQueries
	t.Internal = st.Internal
	t.Retried, t.Recovered = st.Retried, st.Recovered
	t.RateBackoffs, t.FinalRate = st.RateBackoffs, st.FinalRate
	t.PoolHits, t.Confirmed, t.Unconfirmed = st.PoolHits, st.Confirmed, st.Unconfirmed
	t.Wildcard = st.Wildcard
	if st.Wildcard {
		t.Fingerprint = st.Fingerprint
	}
	t.Verdict, t.Reason = st.Verdict(status == StatusInterrupted)
	if st.Wildcard && t.Verdict == scan.VerdictComplete {
		t.Reason += fmt.Sprintf("; wildcard zone, %d answers filtered by fingerprint", st.WildcardFiltered)
	}
	return t
}

// Sources adds a row per passive-source lookup to t, and the CT fields kept
// from before the rows existed. foundBy counts, per source, the found names
// it proposed.
func Sources(t *output.TargetSummary, lookups []passive.Lookup, foundBy map[string]int) {
	for _, l := range lookups {
		t.Sources = append(t.Sources, output.SourceSummary{Name: l.Source, Names: len(l.Names), Found: foundBy[l.Source], Error: l.Err, Truncated: l.Truncated != ""})
		if l.Source == "ct" {
			t.CTNames, t.CTError = len(l.Names), l.Err
		}
	}
}

// Build is a finished run's summary: New, then Finish with the targets, and
// the -r pool's per-resolver accounting when the run had one (pool non-nil).
func Build(r Run, targets []output.TargetSummary, pool *dns.Pool, elapsed time.Duration) output.Summary {
	s := New(r)
	Finish(&s, targets, elapsed)
	if pool != nil {
		s.Resolvers = pool.Stats()
	}
	return s
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
