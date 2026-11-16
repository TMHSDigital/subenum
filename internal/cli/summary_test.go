package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/report"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// TestE2EPermuteReportCountsThePass is #298: the run-quality report of a
// -permute run counts the permutation pass's queries, in the target and in
// the run, on top of what the same scan sends without -permute.
func TestE2EPermuteReportCountsThePass(t *testing.T) {
	t.Parallel()
	type summary struct {
		QueriesSent int64 `json:"queries_sent"`
		Targets     []struct {
			QueriesSent int64 `json:"queries_sent"`
			Processed   int64 `json:"processed"`
			Permutation *struct {
				Candidates  int64 `json:"candidates"`
				Processed   int64 `json:"processed"`
				QueriesSent int64 `json:"queries_sent"`
			} `json:"permutation"`
		} `json:"targets"`
	}
	run := func(extra ...string) summary {
		t.Helper()
		stats := filepath.Join(t.TempDir(), "run.json")
		args := []string{"-simulate-zone", filepath.Join("examples", "labs", "lab1-first-scan.zone"),
			"-w", "examples/labs/words.txt", "-progress=false", "-stats", stats}
		args = append(args, labTimingArgs...)
		args = append(args, extra...)
		if code, _ := runCLI(t, "", append(args, "lab.example")...); code != 0 {
			t.Fatalf("%v: exit %d", extra, code)
		}
		data, err := os.ReadFile(stats)
		if err != nil {
			t.Fatal(err)
		}
		var sum summary
		if err := json.Unmarshal(data, &sum); err != nil || len(sum.Targets) != 1 {
			t.Fatalf("%v: bad -stats report (err %v): %s", extra, err, data)
		}
		return sum
	}
	plain, permuted := run(), run("-permute")
	if plain.Targets[0].Permutation != nil {
		t.Fatal("a run without -permute reports a permutation pass")
	}
	p := permuted.Targets[0].Permutation
	if p == nil || p.Candidates == 0 || p.Processed != p.Candidates || p.QueriesSent < p.Candidates {
		t.Fatalf("permutation = %+v, want every candidate processed and its queries counted", p)
	}
	base := plain.Targets[0].QueriesSent
	if base == 0 || plain.QueriesSent != base {
		t.Fatalf("without -permute: queries_sent = %d (run %d), want the same and above 0", base, plain.QueriesSent)
	}
	if got, want := permuted.Targets[0].QueriesSent, base+p.QueriesSent; got != want {
		t.Errorf("with -permute: target queries_sent = %d, want %d (main pass %d + permutation pass %d)", got, want, base, p.QueriesSent)
	}
	if permuted.QueriesSent != permuted.Targets[0].QueriesSent {
		t.Errorf("with -permute: run queries_sent = %d, target %d", permuted.QueriesSent, permuted.Targets[0].QueriesSent)
	}
	if permuted.Targets[0].Processed != plain.Targets[0].Processed {
		t.Errorf("processed = %d with -permute, %d without: it counts the main pass only", permuted.Targets[0].Processed, plain.Targets[0].Processed)
	}
}

// TestTargetSummaryPermutationVerdict is #298: a permutation pass that went
// worse than the main pass sets the target's verdict, and so the run's, with
// a reason that names the pass.
func TestTargetSummaryPermutationVerdict(t *testing.T) {
	done := func(st scan.Stats) targetResult {
		n := st.Sum()
		return targetResult{done: true, final: scan.Event{Kind: scan.EventDone, Stats: st, Processed: n, Total: n, Found: st.Found}}
	}
	clean := scan.Stats{Found: 2, NXDomain: 38, QueriesSent: 80}
	cases := []struct {
		name    string
		main    scan.Stats
		pass    targetResult
		verdict string
		reason  string // a substring; "permutation pass" must be absent when empty
		queries int64
	}{
		{"both complete", clean, done(scan.Stats{NXDomain: 100, QueriesSent: 200}), scan.VerdictComplete, "", 280},
		{"pass degraded", clean, done(scan.Stats{NXDomain: 90, Timeout: 10, QueriesSent: 220}), scan.VerdictDegraded,
			"permutation pass: 10 of 100 lookups failed", 300},
		{"pass budget spent", clean, done(scan.Stats{NXDomain: 50, Skipped: 50, QueriesSent: 100}), scan.VerdictDegraded,
			"permutation pass: -max-queries reached; 50 candidates not tested", 180},
		{"pass aborted", clean, done(scan.Stats{NXDomain: 10, Timeout: 40, Aborted: true, QueriesSent: 100}), scan.VerdictUnreliable,
			"permutation pass: the reliability guard aborted the scan", 180},
		{"pass did not finish", clean, targetResult{err: "preflight failed"}, scan.VerdictDegraded,
			"permutation pass: preflight failed", 80},
		{"main worse", scan.Stats{NXDomain: 10, Timeout: 30, QueriesSent: 80}, done(scan.Stats{NXDomain: 95, Timeout: 5, QueriesSent: 200}),
			scan.VerdictUnreliable, "", 280},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := done(c.main)
			res.permutation = &permutationResult{seeds: 2, candidates: 100, pass: c.pass}
			got := targetSummary("a.example", "ok", res)
			if got.Verdict != c.verdict || !strings.Contains(got.Reason, c.reason) {
				t.Errorf("verdict = %q (%s), want %q with reason %q", got.Verdict, got.Reason, c.verdict, c.reason)
			}
			if c.reason == "" && strings.Contains(got.Reason, "permutation pass") {
				t.Errorf("reason = %q, want the main pass's", got.Reason)
			}
			if got.QueriesSent != c.queries {
				t.Errorf("queries_sent = %d, want %d", got.QueriesSent, c.queries)
			}
			var sum output.Summary
			report.Finish(&sum, []output.TargetSummary{got}, time.Second)
			if sum.Verdict != got.Verdict || sum.Reason != got.Reason || sum.QueriesSent != c.queries {
				t.Errorf("run = %q (%s), %d queries; target = %q (%s), %d", sum.Verdict, sum.Reason, sum.QueriesSent, got.Verdict, got.Reason, c.queries)
			}
		})
	}
}
