package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// jsonlRecords splits -format jsonl output into results and the summary.
func jsonlRecords(t *testing.T, out string) ([]output.Result, output.Summary) {
	t.Helper()
	var results []output.Result
	var summary output.Summary
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, `"type":"summary"`) {
			if err := json.Unmarshal([]byte(line), &summary); err != nil {
				t.Fatalf("summary: %v", err)
			}
			continue
		}
		var r output.Result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		results = append(results, r)
	}
	return results, summary
}

func resultNames(results []output.Result) map[string]bool {
	set := map[string]bool{}
	for _, r := range results {
		set[r.Subdomain] = true
	}
	return set
}

// writeState saves a hand-built resume state and returns its path.
func writeState(t *testing.T, st resumeState) string {
	t.Helper()
	st.Version = resumeStateVersion
	path := filepath.Join(t.TempDir(), "state.json")
	if err := writeResumeState(path, st); err != nil {
		t.Fatal(err)
	}
	return path
}

// candidatesFor rebuilds a target's -permute candidate list from its
// main-pass names, as runPermutationPass does.
func candidatesFor(target string, entries []string, found []string) []string {
	c, _ := permutationCandidates(target, entries, relativeSeeds(target, found, nil))
	return c
}

// TestE2EResumePermute covers #107: resuming after the main pass, or partway
// through the permutation pass, gives the uninterrupted run's result set
// instead of skipping the permutation pass.
func TestE2EResumePermute(t *testing.T) {
	words := "api\ndev\nwww\nmail\nshop\nblog\nvpn\ncdn\n"
	wl := writeFile(t, "wl.txt", words)
	args := []string{"-simulate", "-seed", "11", "-hit-rate", "40", "-progress=false", "-format", "jsonl", "-permute", "-w", wl, "example.com"}
	code, ref := runCLI(t, "", args...)
	if code != 0 {
		t.Fatalf("reference run: exit %d", code)
	}
	refResults, _ := jsonlRecords(t, ref)
	var mainResults, permResults []output.Result
	for _, r := range refResults {
		if r.Permutation {
			permResults = append(permResults, r)
		} else {
			mainResults = append(mainResults, r)
		}
	}
	if len(mainResults) == 0 || len(permResults) == 0 {
		t.Fatalf("reference run found %d main and %d permutation names; adjust the seed", len(mainResults), len(permResults))
	}
	entries, _, _ := wordlist.Build(strings.Split(words, "\n"), "example.com")
	want := resultNames(refResults)

	// Interrupted between the passes: the main pass is complete.
	mainOnly := resumeTarget{Domain: "example.com", RootDone: len(entries), Processed: int64(len(entries)), Results: mainResults}
	path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{mainOnly}})
	code, out := runCLI(t, "", "-resume", path)
	if code != 0 {
		t.Fatalf("resume after the main pass: exit %d", code)
	}
	if got, _ := jsonlRecords(t, out); !maps.Equal(resultNames(got), want) {
		t.Errorf("resume after the main pass: %d names, want %d", len(got), len(want))
	}

	// Interrupted halfway through the permutation pass.
	candidates := candidatesFor("example.com", entries, mainPassNames(mainResults))
	half := len(candidates) / 2
	before := map[string]bool{}
	for _, c := range candidates[:half] {
		before[c+".example.com"] = true
	}
	partial := mainOnly
	partial.Results = append([]output.Result(nil), mainResults...)
	for _, r := range permResults {
		if before[r.Subdomain] {
			partial.Results = append(partial.Results, r)
		}
	}
	partial.Permute = &resumePass{RootDone: half, Processed: int64(half)}
	path = writeState(t, resumeState{Args: args, Targets: []resumeTarget{partial}})
	code, out = runCLI(t, "", "-resume", path)
	if code != 0 {
		t.Fatalf("resume in the permutation pass: exit %d", code)
	}
	got, summary := jsonlRecords(t, out)
	if !maps.Equal(resultNames(got), want) {
		t.Errorf("resume in the permutation pass: %d names, want %d", len(got), len(want))
	}
	if p := summary.Targets[0].Permutation; p == nil || p.Found != len(permResults) {
		t.Errorf("permutation summary %+v, want %d found", p, len(permResults))
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the finished run's state file was not removed (err %v)", err)
	}
}

// TestE2EResumeKeepsQueryBudget covers #108: a resumed scan gets only what
// is left of -max-queries, and none once it is spent.
func TestE2EResumeKeepsQueryBudget(t *testing.T) {
	var words strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&words, "host%d\n", i)
	}
	wl := writeFile(t, "wl.txt", words.String())
	args := []string{"-simulate", "-seed", "3", "-progress=false", "-format", "jsonl", "-max-queries", "30", "-w", wl, "example.com"}
	for _, c := range []struct{ processed, want int64 }{{20, 30}, {30, 30}} {
		path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{{Domain: "example.com", RootDone: int(c.processed), Processed: c.processed}}})
		code, out := runCLI(t, "", "-resume", path)
		if code != 0 {
			t.Fatalf("processed %d: exit %d", c.processed, code)
		}
		if _, s := jsonlRecords(t, out); s.Targets[0].Processed != c.want {
			t.Errorf("saved %d processed: the resumed run ended at %d, want %d (-max-queries 30)", c.processed, s.Targets[0].Processed, c.want)
		}
	}
}

// TestE2EResumeRefusesChangedSettings covers #109: an env or config value
// that changed since the interrupt, or a different wordlist, refuses to
// resume instead of continuing with other inputs.
func TestE2EResumeRefusesChangedSettings(t *testing.T) {
	wl := writeFile(t, "wl.txt", "www\napi\n")
	args := []string{"-simulate", "-seed", "3", "-progress=false", "-w", wl, "example.com"}
	settings := map[string]string{"depth": "1"}
	path := writeState(t, resumeState{Args: args, Settings: settings, Targets: []resumeTarget{{Domain: "example.com"}}})
	t.Setenv("SUBENUM_DEPTH", "2")
	if code, out := runCLIMerged(t, "-resume", path); code != exitFailure || !strings.Contains(out, "SUBENUM_DEPTH") {
		t.Errorf("changed SUBENUM_DEPTH: exit %d\n%s", code, out)
	}
	t.Setenv("SUBENUM_DEPTH", "")

	path = writeState(t, resumeState{Args: args, Targets: []resumeTarget{{Domain: "example.com", Entries: "0123"}}})
	if code, out := runCLIMerged(t, "-resume", path); code != exitFailure || !strings.Contains(out, "wordlist for example.com changed") {
		t.Errorf("changed entries: exit %d\n%s", code, out)
	}
}

// TestSaveResumeStateKeepsEarlierPosition covers #109: a resumed target
// interrupted again before its scan reported progress, and a target the run
// never reached, keep their saved resume points.
func TestSaveResumeStateKeepsEarlierPosition(t *testing.T) {
	prev := &resumeState{Targets: []resumeTarget{
		{Domain: "a.example", RootDone: 40, Processed: 40, Stats: scan.Stats{NXDomain: 38}, Results: []output.Result{{Subdomain: "x.a.example"}}},
		{Domain: "b.example", RootDone: 7, Processed: 7, Permute: &resumePass{RootDone: 3}},
	}}
	f := cliFlags{stateFile: filepath.Join(t.TempDir(), "state.json"), wordlistFile: ""}
	out := output.New(nil, false, output.FormatText)
	targets := []string{"a.example", "b.example"}
	saveResumeState(f, nil, nil, prev, targets, []string{"interrupted", ""}, []string{"d1", ""},
		[]targetResult{{}, {}}, [][]output.Result{{{Subdomain: "x.a.example"}}, nil}, out)
	data, err := os.ReadFile(f.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	var st resumeState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	a, b := st.Targets[0], st.Targets[1]
	if a.RootDone != 40 || a.Processed != 40 || a.Stats.NXDomain != 38 || a.Entries != "d1" {
		t.Errorf("re-interrupted target lost its position: %+v", a)
	}
	if b.RootDone != 7 || b.Permute == nil || b.Permute.RootDone != 3 {
		t.Errorf("unreached target lost its state: %+v", b)
	}
}

// TestE2EPermuteRecursive covers #111: -permute with -recursive runs the
// permutation pass one level deep, so no name is built from a candidate
// under another candidate and the pass is not refused.
func TestE2EPermuteRecursive(t *testing.T) {
	words := "api\ndev\nwww\nmail\n"
	wl := writeFile(t, "wl.txt", words)
	code, out := runCLI(t, "", "-simulate", "-seed", "5", "-hit-rate", "50", "-progress=false", "-format", "jsonl",
		"-permute", "-recursive", "-depth", "2", "-w", wl, "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	results, _ := jsonlRecords(t, out)
	entries, _, _ := wordlist.Build(strings.Split(words, "\n"), "example.com")
	candidates := map[string]bool{}
	for _, c := range candidatesFor("example.com", entries, mainPassNames(results)) {
		candidates[c+".example.com"] = true
	}
	perms := 0
	for _, r := range results {
		if !r.Permutation {
			continue
		}
		perms++
		if !candidates[r.Subdomain] {
			t.Errorf("permutation result %s is not a permutation candidate", r.Subdomain)
		}
	}
	if perms == 0 {
		t.Fatal("no permutation results; adjust the seed")
	}
}

// TestPermutationCandidatesRespectNameLength covers #111: candidates whose
// full name passes 253 characters are dropped, not queried.
func TestPermutationCandidatesRespectNameLength(t *testing.T) {
	label := strings.Repeat("a", 60)
	target := strings.Join([]string{label, label, label, "example"}, ".") // 191 characters
	seed := strings.Repeat("b", 55) + "." + target                        // 247 characters
	candidates, tooLong := permutationCandidates(target, nil, relativeSeeds(target, []string{seed}, nil))
	if tooLong == 0 || len(candidates) == 0 {
		t.Fatalf("%d candidates, %d too long; want some of each", len(candidates), tooLong)
	}
	for _, c := range candidates {
		if n := len(c) + 1 + len(target); n > 253 {
			t.Errorf("candidate %s is %d characters long", c, n)
		}
	}
}
