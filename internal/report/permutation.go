package report

import (
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// PermutationReason starts a target's verdict reason when the verdict is
// the -permute pass's (#298).
const PermutationReason = "permutation pass: "

// PermutationPass is how a target's -permute pass went, for Permutation.
type PermutationPass struct {
	Seeds, Candidates, Found int
	// Final is the pass's last event when it ran and reported its counts;
	// nil when it did not get through its candidates (stopped first, or it
	// failed before them).
	Final *scan.Event
	// Failure says why a pass that did not report its counts stopped; empty
	// means it did not run to completion.
	Failure string
}

// Permutation adds a target's -permute pass to t, the same way for the
// command line and the TUI (#298, #347): its counts and queries, and its
// verdict when that is worse than the main pass's. A pass with candidates
// that never reported its counts makes the target at least degraded.
// interrupted is whether the run was interrupted; name renders the
// settings a reason names.
func Permutation(t *output.TargetSummary, p PermutationPass, interrupted bool, name func(scan.Setting) string) {
	t.Permutation = &output.PermutationSummary{Seeds: p.Seeds, Candidates: p.Candidates, Found: p.Found}
	switch {
	case p.Final != nil:
		final := p.Final
		verdict, reason := final.Stats.Verdict(interrupted)
		t.Permutation.Verdict = verdict
		t.Permutation.Processed, t.Permutation.QueriesSent = final.Processed, final.Stats.QueriesSent
		t.QueriesSent += final.Stats.QueriesSent
		if scan.VerdictRank(verdict) > scan.VerdictRank(t.Verdict) {
			t.Verdict, t.Reason = verdict, PermutationReason+scan.Render(reason, name)
		}
	case p.Candidates > 0 && scan.VerdictRank(t.Verdict) < scan.VerdictRank(scan.VerdictDegraded):
		failure := p.Failure
		if failure == "" {
			failure = "it did not run to completion"
		}
		t.Verdict, t.Reason = scan.VerdictDegraded, PermutationReason+failure
	}
}
