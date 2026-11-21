package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestE2ELabDanglingDelegation covers #406 on the built-in Lab 9: legacy's
// every name server is gone, so the lab's resolver answers SERVFAIL for it;
// under -type NS the zone's own server is asked for the delegation, and
// legacy is flagged dangling-ns, with the check in the run-quality report.
// staging, whose name server answers, is not flagged; without NS in -type,
// legacy stays inconclusive and nothing is asked.
func TestE2ELabDanglingDelegation(t *testing.T) {
	t.Parallel()
	wl := writeFile(t, "w.txt", "www\nlegacy\nstaging\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	args := append([]string{"-simulate-zone", "lab9", "-w", wl, "-format", "jsonl", "-progress=false", "-rate", "200", "-stats", stats}, labTimingArgs...)
	code, out := runCLIMerged(t, append(args, "-type", "A,NS", "lab.example")...)
	got := seenResults(t, lastJSONLines(out))
	if code != exitOK || got["legacy.lab.example"].Takeover != "dangling-ns" {
		t.Fatalf("exit %d, results %v, want legacy flagged dangling-ns\n%s", code, got, out)
	}
	if recs := got["legacy.lab.example"].Records; len(recs) != 2 || recs[0].Value != "ns1.legacy-dns.example" {
		t.Errorf("legacy records = %v, want its two gone name servers", recs)
	}
	if r, ok := got["staging.lab.example"]; !ok || r.Takeover != "" {
		t.Errorf("staging = %+v (found %v), want reported without a hint", r, ok)
	}
	tg := axfrSummary(t, stats).Targets[0]
	if tg.ParentChecks != 1 || tg.ParentQueries != 1 || tg.Takeover != 1 || tg.Outcomes.Other != 0 {
		t.Errorf("report: parent_checks %d, parent_queries %d, takeover %d, other %d; want 1, 1, 1, 0", tg.ParentChecks, tg.ParentQueries, tg.Takeover, tg.Outcomes.Other)
	}

	code, out = runCLIMerged(t, append(args, "lab.example")...)
	got = seenResults(t, lastJSONLines(out))
	if _, ok := got["legacy.lab.example"]; code != exitOK || ok {
		t.Errorf("without NS: exit %d, results %v, want legacy not reported\n%s", code, got, out)
	}
	if tg := axfrSummary(t, stats).Targets[0]; tg.ParentChecks != 0 || tg.Outcomes.Other != 1 || strings.Contains(out, "parent_checks") {
		t.Errorf("without NS: parent_checks %d, other %d; want 0 and 1", tg.ParentChecks, tg.Outcomes.Other)
	}
}
