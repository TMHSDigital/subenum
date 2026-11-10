package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
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

// TestResumeArgsParsing covers #166: an empty -resume= is an error, and
// -resume after "--" is a positional argument, not the flag.
func TestResumeArgsParsing(t *testing.T) {
	for _, args := range [][]string{{"-resume="}, {"--resume="}, {"-resume"}} {
		if _, _, err := resumeArgs(args); err == nil || !strings.Contains(err.Error(), "needs a state file") {
			t.Errorf("%q: err = %v, want \"needs a state file\"", args, err)
		}
	}
	args := []string{"-simulate", "--", "-resume"}
	got, st, err := resumeArgs(args)
	if err != nil || st != nil || len(got) != len(args) {
		t.Errorf("-resume after --: got %q, state %v, err %v; want the arguments unchanged", got, st, err)
	}
	path := writeState(t, resumeState{Args: []string{"-simulate", "example.com"}})
	for _, args := range [][]string{{"-resume", path}, {"--resume=" + path}} {
		if got, st, err := resumeArgs(args); err != nil || st == nil || len(got) != 2 {
			t.Errorf("%q: got %q, err %v", args, got, err)
		}
	}
}

// TestE2EResumeCountsRefoundNamesOnce covers #156: the resume point lags the
// saved results by up to a worker pool's worth of names, so a resumed scan
// finds some of them again; they are counted once.
func TestE2EResumeCountsRefoundNamesOnce(t *testing.T) {
	var words strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&words, "host%d\n", i)
	}
	wl := writeFile(t, "wl.txt", words.String())
	args := []string{"-simulate", "-seed", "5", "-hit-rate", "100", "-t", "1", "-progress=false", "-format", "jsonl", "-w", wl, "example.com"}
	entries, _, _ := wordlist.Build(strings.Split(words.String(), "\n"), "example.com")
	// Ten names were found and processed, but only the first five entries
	// were complete when the scan was interrupted.
	var saved []output.Result
	for _, e := range entries[:10] {
		saved = append(saved, output.Result{Result: scan.Result{Subdomain: e + ".example.com"}})
	}
	path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{{
		Domain: "example.com", RootDone: 5, Processed: 10, Total: int64(len(entries)), Results: saved,
		Stats: scan.Stats{Found: 10},
	}}})
	code, out := runCLI(t, "", "-resume", path)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	got, s := jsonlRecords(t, out)
	if len(resultNames(got)) != len(entries) {
		t.Fatalf("%d unique names, want %d", len(resultNames(got)), len(entries))
	}
	if tg := s.Targets[0]; tg.Found != int64(len(entries)) || tg.Processed != int64(len(entries)) {
		t.Errorf("found %d, processed %d; want %d each", tg.Found, tg.Processed, len(entries))
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
		{Domain: "a.example", RootDone: 40, Processed: 40, Stats: scan.Stats{NXDomain: 38}, Results: []output.Result{{Result: scan.Result{Subdomain: "x.a.example"}}}},
		{Domain: "b.example", RootDone: 7, Processed: 7, Permute: &resumePass{RootDone: 3}},
	}}
	f := cliFlags{stateFile: filepath.Join(t.TempDir(), "state.json")}
	out := output.New(nil, false, output.FormatText)
	saveResumeState(&session{
		f: f, out: out, resume: prev,
		targets:      []string{"a.example", "b.example"},
		status:       []string{"interrupted", ""},
		entryDigests: []string{"d1", ""},
		results:      []targetResult{{}, {}},
		runs:         [][]output.Result{{{Result: scan.Result{Subdomain: "x.a.example"}}}, nil},
	})
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

// TestSaveResumeStateRecordsFinishedPermutePass covers #174: a -permute pass
// that finished before the interrupt is saved from its final EventDone, field
// for field, and replays as that same event on resume.
func TestSaveResumeStateRecordsFinishedPermutePass(t *testing.T) {
	final := scan.Event{
		Kind:      scan.EventDone,
		Stats:     scan.Stats{RootDone: 12, Found: 3, NXDomain: 9},
		Processed: 12,
		Total:     12,
		Found:     3,
	}
	f := cliFlags{stateFile: filepath.Join(t.TempDir(), "state.json")}
	saveResumeState(&session{
		f: f, out: output.New(nil, false, output.FormatText),
		targets:      []string{"a.example"},
		status:       []string{"interrupted"},
		entryDigests: []string{"d1"},
		results: []targetResult{{
			done:        true,
			final:       scan.Event{Kind: scan.EventDone, Stats: scan.Stats{RootDone: 40}, Processed: 40, Total: 40},
			permutation: &permutationResult{candidates: 12, pass: targetResult{done: true, final: final}},
		}},
		runs: [][]output.Result{nil},
	})
	data, err := os.ReadFile(f.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	var st resumeState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	p := st.Targets[0].Permute
	if p == nil {
		t.Fatal("finished permute pass not saved")
	}
	want := resumePass{RootDone: 12, Stats: final.Stats, Processed: 12, Total: 12, Found: 3}
	if !reflect.DeepEqual(*p, want) {
		t.Errorf("saved pass = %+v, want %+v", *p, want)
	}
	if ev := p.event(); !reflect.DeepEqual(ev, final) {
		t.Errorf("replayed event = %+v, want %+v", ev, final)
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

// TestMergeStatsCoversEveryField is the drift guard of #162: a field added to
// scan.Stats that mergeStats drops fails here. Each field set in either the
// saved or the resumed run must survive the merge; RootDone is the one field
// taken from the resumed run alone.
func TestMergeStatsCoversEveryField(t *testing.T) {
	zero := mergeStats(scan.Stats{}, scan.Stats{})
	st := reflect.TypeOf(scan.Stats{})
	for i := range st.NumField() {
		name := st.Field(i).Name
		for _, side := range []string{"saved", "resumed"} {
			if side == "saved" && name == "RootDone" {
				continue
			}
			var a, b scan.Stats
			v := reflect.ValueOf(&b).Elem().Field(i)
			if side == "saved" {
				v = reflect.ValueOf(&a).Elem().Field(i)
			}
			switch v.Kind() {
			case reflect.Int64:
				v.SetInt(1)
			case reflect.Bool:
				v.SetBool(true)
			case reflect.Slice:
				v.Set(reflect.ValueOf([]dns.Record{{Type: "A", Value: "192.0.2.1"}}))
			default:
				t.Fatalf("scan.Stats.%s: unhandled kind %s", name, v.Kind())
			}
			if got := mergeStats(a, b); reflect.DeepEqual(got, zero) {
				t.Errorf("mergeStats drops scan.Stats.%s from the %s run", name, side)
			}
		}
	}
}
