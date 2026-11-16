package cli

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/report"
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
	c, _ := candidates.Permutations(target, entries, candidates.RelativeSeeds(target, found, nil))
	return c
}

// TestE2EResumePermute covers #107: resuming after the main pass, or partway
// through the permutation pass, gives the uninterrupted run's result set
// instead of skipping the permutation pass.
func TestE2EResumePermute(t *testing.T) {
	t.Parallel()
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

// TestResumeArgsPacing covers #309: the pacing flags may be given next to
// -resume and are applied over the replayed arguments, before any "--";
// every other argument is refused.
func TestResumeArgsPacing(t *testing.T) {
	path := writeState(t, resumeState{Args: []string{"-simulate", "-rate", "20", "--", "example.com"}})
	got, _, err := resumeArgs([]string{"-t", "4", "-resume", path, "--rate=5", "-auto-rate", "-max-duration", "1h"})
	want := []string{"-simulate", "-rate", "20", "-t=4", "--rate=5", "-auto-rate", "-max-duration=1h", "--", "example.com"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("got %q, err %v; want %q", got, err, want)
	}
	for _, extra := range [][]string{{"-type", "A"}, {"-w", "words.txt"}, {"example.com"}, {"-rate"}, {"--", "-rate", "5"}} {
		if _, _, err := resumeArgs(append([]string{"-resume", path}, extra...)); err == nil {
			t.Errorf("-resume with %q: no error", extra)
		}
	}
}

// TestE2EResumeChangesPacing covers #309: a scan stopped while slow resumes
// at another rate; the override is checked against nothing frozen, recorded
// in the next state file, and the scan still finishes complete. Flags that
// change the candidates stay refused.
func TestE2EResumeChangesPacing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	const n = 120
	var words strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&words, "host%d\n", i)
	}
	wl := writeFile(t, "wl.txt", words.String())
	base := []string{"-simulate", "-seed", "3", "-hit-rate", "50", "-progress=false", "-format", "jsonl", "-w", wl}
	names := func(out string) map[string]bool {
		results, _ := jsonlRecords(t, out)
		return resultNames(results)
	}
	_, ref := runCLI(t, "", append(slices.Clone(base), "example.com")...)
	want := names(ref)

	// -rate 20 with 120 words needs about 6 s; the budget is 1 s.
	code, out := runCLIMerged(t, append(slices.Clone(base), "-t", "1", "-rate", "20", "-max-duration", "1s", "-state", state, "example.com")...)
	if code != 0 {
		t.Fatalf("first run: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("first run saved no state: %v", err)
	}
	// Flags that change the candidate list stay frozen.
	if code, out := runCLIMerged(t, "-resume", state, "-type", "A"); code != exitUsage || !strings.Contains(out, "pacing flags") {
		t.Fatalf("-resume -type A: exit %d, want %d\n%s", code, exitUsage, out)
	}

	// A resumed run at another, still slow rate stops again and records it.
	if code, out := runCLIMerged(t, "-resume", state, "-rate", "40"); code != 0 {
		t.Fatalf("resume at -rate 40: exit %d\n%s", code, out)
	}
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatalf("resume at -rate 40 saved no state: %v", err)
	}
	var st resumeState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(st.Args, "-rate=40") || st.Settings["rate"] != "40" {
		t.Fatalf("saved args %q, rate setting %q; want the -rate 40 override recorded", st.Args, st.Settings["rate"])
	}

	// Unthrottled and with a budget it cannot spend, the scan finishes.
	code, out = runCLI(t, "", "-resume", state, "-rate", "0", "-t", "8", "-max-duration", "1h")
	if code != 0 {
		t.Fatalf("unthrottled resume: exit %d", code)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Errorf("the finished run's state file was not removed (err %v)", err)
	}
	if got := names(out); !maps.Equal(got, want) {
		t.Errorf("resumed scan reported %d names, uninterrupted %d", len(got), len(want))
	}
}

// TestE2EResumeCountsRefoundNamesOnce covers #156: the resume point lags the
// saved results by up to a worker pool's worth of names, so a resumed scan
// finds some of them again; they are counted once.
func TestE2EResumeCountsRefoundNamesOnce(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// TestE2EMaxDurationSavesResumeState covers #294: a run that -max-duration
// stops with names untested exits 0, saves a resume state and says how to
// continue; a resumed run that expires again keeps a state file, further
// along; and the run that tests the last names removes it and is complete.
func TestE2EMaxDurationSavesResumeState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	state, stats := filepath.Join(dir, "state.json"), filepath.Join(dir, "run.json")
	const n = 120
	var words strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&words, "host%d\n", i)
	}
	// -rate 50 with 120 words needs about 2.4 s; each run's budget is 1 s, so
	// the first two runs cannot finish.
	code, out := runCLIMerged(t, "-simulate", "-seed", "3", "-progress=false", "-t", "2", "-rate", "50",
		"-max-duration", "1s", "-state", state, "-stats", stats, "-w", writeFile(t, "wl.txt", words.String()), "example.com")
	if code != 0 {
		t.Fatalf("exit %d, want 0 for a spent budget\n%s", code, out)
	}
	if want := "continue with: subenum -resume " + state; !strings.Contains(out, want) {
		t.Fatalf("output lacks %q\n%s", want, out)
	}
	position := func() int {
		t.Helper()
		data, err := os.ReadFile(state)
		if err != nil {
			t.Fatalf("no resume state: %v", err)
		}
		var st resumeState
		if err := json.Unmarshal(data, &st); err != nil {
			t.Fatal(err)
		}
		if len(st.Targets) != 1 || st.Targets[0].Done {
			t.Fatalf("saved targets %+v, want one that is not done", st.Targets)
		}
		return st.Targets[0].RootDone
	}
	first := position()
	if first <= 0 || first >= n {
		t.Fatalf("resume point %d, want within the %d words", first, n)
	}

	// The budget is per invocation, so the resumed run expires again.
	if code, out := runCLIMerged(t, "-resume", state); code != 0 {
		t.Fatalf("resumed run: exit %d\n%s", code, out)
	}
	if second := position(); second <= first {
		t.Fatalf("resume point %d after the resumed run, want past %d", second, first)
	}

	for i := 0; ; i++ {
		if _, err := os.Stat(state); err != nil {
			break // the run that finished removed its state
		}
		if i == 20 {
			t.Fatal("the scan did not finish in 20 more resumed runs")
		}
		if code, out := runCLIMerged(t, "-resume", state); code != 0 {
			t.Fatalf("resumed run: exit %d\n%s", code, out)
		}
	}
	data, err := os.ReadFile(stats)
	if err != nil {
		t.Fatal(err)
	}
	var sum struct {
		Verdict string `json:"verdict"`
		Targets []struct {
			Processed  int64  `json:"processed"`
			SkippedCap int64  `json:"skipped_by_cap"`
			StoppedBy  string `json:"stopped_by"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Verdict != "complete" || len(sum.Targets) != 1 || sum.Targets[0].SkippedCap != 0 || sum.Targets[0].StoppedBy != "" || sum.Targets[0].Processed < n {
		t.Errorf("finished scan: verdict %q, targets %+v; want complete with all %d words tested and none skipped", sum.Verdict, sum.Targets, n)
	}
}

// TestE2EResumeRetriesEarlierInconclusive covers #315: a name that timed out
// before an interrupt, whose -retry-inconclusive pass never ran, is retried
// by the resumed run, and leaves the -inconclusive list once it answers.
func TestE2EResumeRetriesEarlierInconclusive(t *testing.T) {
	t.Parallel()
	words := []string{"flaky"}
	for i := 0; i < 20; i++ {
		words = append(words, fmt.Sprintf("host%d", i))
	}
	wl := writeFile(t, "wl.txt", strings.Join(words, "\n")+"\n")
	signals := make(chan os.Signal, 1)
	var stopped atomic.Bool
	var once sync.Once
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Name == "example.test" && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"192.0.2.1"}}
		case q.Name == "flaky.example.test":
			if !stopped.Load() {
				return dnstest.Dropped // a timeout, until the run is interrupted
			}
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"192.0.2.7"}}
			}
		case q.Name == "host12.example.test":
			// Past the first chunk, so flaky is before the resume point.
			once.Do(func() {
				stopped.Store(true)
				signals <- os.Interrupt
			})
		}
		return dnstest.NXDomain
	})
	dir := t.TempDir()
	state, incon, out := filepath.Join(dir, "state.json"), filepath.Join(dir, "incon.txt"), filepath.Join(dir, "results.txt")
	// One worker in order; a short timeout for the one name that never
	// answers, two tries for the rest.
	code, first := runCLIMergedWith(t, runArgs{signals: signals, args: []string{"-dns-server", srv.Addr, "-type", "A", "-progress=false",
		"-t", "1", "-timeout", "1000", "-attempts", "1", "-retry-inconclusive", "-inconclusive", incon,
		"-state", state, "-o", out, "-w", wl, "example.test"}})
	if code != 130 {
		t.Fatalf("interrupted run: exit %d, want 130\n%s", code, first)
	}
	var st resumeState
	if data, err := os.ReadFile(state); err != nil || json.Unmarshal(data, &st) != nil || len(st.Targets) != 1 ||
		!slices.Contains(st.Targets[0].Pending, savedPending{Name: "flaky.example.test", Outcome: "timeout"}) {
		t.Fatalf("the state does not keep flaky for the retry pass (err %v):\n%s", err, data)
	}
	code, resumed := runCLIMerged(t, "-resume", state)
	if code != 0 {
		t.Fatalf("resumed run: exit %d\n%s", code, resumed)
	}
	if data, err := os.ReadFile(out); err != nil || !strings.Contains(string(data), "flaky.example.test") {
		t.Errorf("the resumed run did not retry and find flaky (err %v):\n%s\n%s", err, data, resumed)
	}
	if data, _ := os.ReadFile(incon); strings.Contains(string(data), "flaky") {
		t.Errorf("flaky is still listed inconclusive:\n%s", data)
	}
}

// TestE2EResumeCountsEachNameOnce covers #341: a run stopped by
// -max-duration and resumed until it finishes reports the counts of an
// uninterrupted run. Before, the stop counted every excluded name past it and
// the resume counted them again, and names looked up in a chunk reported
// after the stop were counted by both runs.
func TestE2EResumeCountsEachNameOnce(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const n = 120
	var words strings.Builder
	var exclude []string
	for i := 0; i < n; i++ {
		fmt.Fprintf(&words, "host%d\n", i)
		if i%10 == 3 {
			exclude = append(exclude, fmt.Sprintf("host%d.example.com", i))
		}
	}
	wl := writeFile(t, "wl.txt", words.String())
	type counts struct {
		Processed, Total, Found int64
		Outcomes                output.Outcomes
	}
	run := func(stats string, extra ...string) (int, string, counts) {
		t.Helper()
		args := append([]string{"-simulate", "-seed", "5", "-hit-rate", "30", "-progress=false", "-t", "4",
			"-w", wl, "-exclude", strings.Join(exclude, ","), "-stats", stats}, extra...)
		code, out := runCLIMerged(t, append(args, "example.com")...)
		return code, out, readCounts(t, stats)
	}
	_, _, want := run(filepath.Join(dir, "full.json"))
	if want.Outcomes.Excluded != int64(len(exclude)) || want.Processed != n-int64(len(exclude)) {
		t.Fatalf("uninterrupted run: %+v, want %d excluded and the rest processed", want, len(exclude))
	}

	// -rate 50 with 108 names needs about 2 s, so a 400 ms budget stops the
	// run, and each resume, several times.
	stats, state := filepath.Join(dir, "stats.json"), filepath.Join(dir, "state.json")
	code, out, _ := run(stats, "-rate", "50", "-max-duration", "400ms", "-state", state)
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("the stopped run (exit %d) saved no resume state: %v\n%s", code, err, out)
	}
	var got counts
	for i := 0; ; i++ {
		if i == 30 {
			t.Fatal("the scan did not finish in 30 resumed runs")
		}
		code, out = runCLIMerged(t, "-resume", state, "-rate", "50", "-max-duration", "400ms")
		got = readCounts(t, stats)
		if got.Processed > got.Total || got.Outcomes.Excluded > want.Outcomes.Excluded {
			t.Fatalf("resumed run %d: %+v; processed above the total, or more excluded than %d\n%s", i, got, want.Outcomes.Excluded, out)
		}
		if _, err := os.Stat(state); err != nil {
			break // the run that finished removed its state
		}
	}
	if code != 0 || got != want {
		t.Errorf("resumed to the end: exit %d, %+v; want exit 0 and the uninterrupted run's %+v\n%s", code, got, want, out)
	}
}

// readCounts reads the one target's counts from a -stats report.
func readCounts(t *testing.T, path string) (c struct {
	Processed, Total, Found int64
	Outcomes                output.Outcomes
}) {
	t.Helper()
	var s output.Summary
	if data, err := os.ReadFile(path); err != nil || json.Unmarshal(data, &s) != nil || len(s.Targets) != 1 {
		t.Fatalf("reading %s: %v", path, err)
	}
	tg := s.Targets[0]
	c.Processed, c.Total, c.Found, c.Outcomes = tg.Processed, tg.Total, tg.Found, tg.Outcomes
	return c
}

// TestE2EResumeDiffOntoOutputFile covers #297: with -diff and -o on one
// file, a run that stops and saves a resume state leaves the file alone, so
// the resumed run reports the same diff and exit code as an uninterrupted
// one, and then writes the full results.
func TestE2EResumeDiffOntoOutputFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const n = 120
	var words strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&words, "host%d\n", i)
	}
	base := []string{"-simulate", "-seed", "3", "-hit-rate", "50", "-progress=false", "-t", "2", "-format", "jsonl",
		"-w", writeFile(t, "wl.txt", words.String())}
	run := func(extra ...string) (int, string) {
		return runCLIMerged(t, append(append(slices.Clone(base), extra...), "example.com")...)
	}
	names := func(path string) []string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		results, _ := jsonlRecords(t, string(data))
		var out []string
		for _, r := range results {
			out = append(out, r.Subdomain)
		}
		slices.Sort(out)
		return out
	}
	diffOf := func(path string) output.DiffSummary {
		t.Helper()
		var summary output.Summary
		if data, err := os.ReadFile(path); err != nil || json.Unmarshal(data, &summary) != nil || summary.Diff == nil {
			t.Fatalf("reading the diff summary in %s: %v", path, err)
		}
		d := *summary.Diff
		d.Previous = ""
		return d
	}

	full := filepath.Join(dir, "full.jsonl")
	if code, out := run("-o", full); code != 0 {
		t.Fatalf("baseline run: exit %d\n%s", code, out)
	}
	all := names(full)
	if len(all) < 10 {
		t.Fatalf("the simulation found %d names, want at least 10", len(all))
	}
	// The baseline lacks one name the scan finds. It holds no name the scan
	// cannot find: such a name is re-checked after the scan, and a resumed
	// run that ends close to its -max-duration reports it unverified instead
	// of removed, which made the comparison below depend on timing.
	baseline := strings.Join(all[1:], "\n") + "\n"

	// The uninterrupted run.
	stats := filepath.Join(dir, "stats.json")
	wantCode, out := run("-diff", writeFile(t, "prev.txt", baseline), "-o", filepath.Join(dir, "cur.jsonl"), "-stats", stats)
	want := diffOf(stats)
	if wantCode != 4 || want.Added != 1 {
		t.Fatalf("uninterrupted run: exit %d, diff %+v; want exit 4 with 1 added\n%s", wantCode, want, out)
	}

	// -rate 50 with 120 words needs about 2.4 s, so a 1 s budget stops the run.
	// A second -o file is not the baseline: it gets the partial results (#334).
	results, state := writeFile(t, "results.txt", baseline), filepath.Join(dir, "state.json")
	extra := filepath.Join(dir, "extra.txt")
	// -o names the baseline another way: it is still the same file (#342).
	respelled := filepath.Dir(results) + string(filepath.Separator) + "." + string(filepath.Separator) + filepath.Base(results)
	code, out := run("-diff", results, "-o", respelled, "-o", "jsonl:"+extra, "-stats", stats, "-rate", "50", "-max-duration", "1s", "-state", state)
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("the stopped run (exit %d) saved no resume state: %v\n%s", code, err, out)
	}
	if data, err := os.ReadFile(results); err != nil || string(data) != baseline {
		t.Fatalf("the stopped run changed its -diff baseline (err %v):\n%s", err, data)
	}
	if _, err := os.Stat(extra); err != nil {
		t.Fatalf("the stopped run did not write its other -o file: %v", err)
	}
	for i := 0; ; i++ {
		if i == 20 {
			t.Fatal("the scan did not finish in 20 resumed runs")
		}
		code, out = runCLIMerged(t, "-resume", state)
		if _, err := os.Stat(state); err != nil {
			break // the run that finished removed its state
		}
		if data, err := os.ReadFile(results); err != nil || string(data) != baseline {
			t.Fatalf("resumed run %d changed its -diff baseline (err %v):\n%s", i, err, data)
		}
	}
	if got := diffOf(stats); code != wantCode || got != want {
		t.Errorf("resumed run: exit %d, diff %+v; want exit %d, diff %+v as uninterrupted\n%s", code, got, wantCode, want, out)
	}
	for _, path := range []string{results, extra} {
		if got := names(path); !slices.Equal(got, all) {
			t.Errorf("-o %s holds %d names after the resumed run, want all %d", path, len(got), len(all))
		}
	}
}

// TestE2EAbortSavesResumeState covers #294: a scan the reliability guard
// aborts fails as before, but saves a resume state, and the resumed run
// tests the rest once the resolver answers again.
func TestE2EAbortSavesResumeState(t *testing.T) {
	t.Parallel()
	const n = 600
	var words strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&words, "host%d\n", i)
	}
	var healthy atomic.Bool
	srv, err := dnsserver.Listen(dnsserver.Options{}, func(q dnsserver.Query) dnsserver.Reply {
		if strings.HasPrefix(q.Name, "host") && !healthy.Load() {
			return dnsserver.Refused
		}
		return dnsserver.NXDomain
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	dir := t.TempDir()
	state, stats := filepath.Join(dir, "state.json"), filepath.Join(dir, "run.json")
	// The server answers at once, so the long timeout costs nothing (#289).
	code, out := runCLIMerged(t, "-progress=false", "-dns-server", srv.Addr, "-timeout", "10000", "-attempts", "1", "-type", "A",
		"-t", "4", "-state", state, "-stats", stats, "-w", writeFile(t, "wl.txt", words.String()), "example.com")
	if code != exitFailure {
		t.Fatalf("aborted run: exit %d, want %d\n%s", code, exitFailure, out)
	}
	if want := "continue with: subenum -resume " + state; !strings.Contains(out, want) {
		t.Fatalf("output lacks %q\n%s", want, out)
	}
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var st resumeState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Targets) != 1 || st.Targets[0].Done || st.Targets[0].RootDone <= 0 || st.Targets[0].RootDone >= n {
		t.Fatalf("saved targets %+v, want one stopped within the %d words", st.Targets, n)
	}

	healthy.Store(true)
	if code, out := runCLIMerged(t, "-resume", state); code != 0 {
		t.Fatalf("resumed run: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(state); err == nil {
		t.Error("the finished run left its resume state behind")
	}
	if data, err = os.ReadFile(stats); err != nil {
		t.Fatal(err)
	}
	var sum struct {
		Targets []struct {
			Processed int64 `json:"processed"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &sum); err != nil {
		t.Fatal(err)
	}
	if len(sum.Targets) != 1 || sum.Targets[0].Processed < n {
		t.Errorf("targets %+v, want all %d words tested over both runs", sum.Targets, n)
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

// TestE2EResumeRefusesBadState covers #255: a changed input file, and a
// state file that is missing, corrupt or from another version, each refuse
// to resume with a message saying which.
func TestE2EResumeRefusesBadState(t *testing.T) {
	t.Parallel()
	wl := writeFile(t, "wl.txt", "www\napi\n")
	args := []string{"-simulate", "-seed", "3", "-progress=false", "-w", wl, "example.com"}
	changed := writeState(t, resumeState{Args: args, Inputs: map[string]string{wl: "digest-of-the-old-file"}, Targets: []resumeTarget{{Domain: "example.com"}}})
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.json")
	future := filepath.Join(dir, "future.json")
	if err := os.WriteFile(corrupt, []byte(`{"version": 1, "args": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(future, []byte(`{"version": 999, "args": ["example.com"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, want string }{
		{changed, "changed since the stopped run"},
		{corrupt, "-resume " + corrupt + ":"},
		{future, "unsupported state version 999"},
		{filepath.Join(dir, "missing.json"), "reading -resume state"},
	} {
		if code, out := runCLIMerged(t, "-resume", tc.path); code == exitOK || !strings.Contains(out, tc.want) {
			t.Errorf("-resume %s: exit %d, want a failure saying %q\n%s", filepath.Base(tc.path), code, tc.want, out)
		}
	}
}

// TestE2EResumeReplaysSourceNames covers #255: a resumed scan reuses the
// names each passive source returned before the interrupt, in the current
// and the legacy (-ct only) state format, and asks no source again.
func TestE2EResumeReplaysSourceNames(t *testing.T) {
	t.Parallel()
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.Name == "legacy.example.com" && q.Type == dnsmessage.TypeA {
			return dnstest.Reply{A: []string{"192.0.2.10"}}
		}
		if q.Name == "legacy.example.com" {
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	var hits atomic.Int32
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`[{"name_value": "other.example.com"}]`))
	}))
	defer ct.Close()
	urls := map[string]string{"ct": ct.URL + "/"}

	wl := writeFile(t, "wl.txt", "www\n")
	for name, tc := range map[string]struct {
		flag  string
		saved resumeTarget
	}{
		"sources": {"-sources=ct", resumeTarget{Domain: "example.com", Sources: map[string][]string{"ct": {"legacy"}}}},
		"legacy":  {"-ct", resumeTarget{Domain: "example.com", CT: []string{"legacy"}, CTFetched: true}},
	} {
		args := append(localArgs(tc.flag, "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-w", wl), "example.com")
		path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{tc.saved}})
		hits.Store(0)
		code, out := runCLIWith(t, runArgs{sourceURLs: urls, args: []string{"-resume", path}})
		if code != 0 || !strings.Contains(out, "legacy.example.com") || strings.Contains(out, "other.example.com") {
			t.Errorf("%s: exit %d, results %q; want the saved name legacy only", name, code, out)
		}
		if hits.Load() != 0 {
			t.Errorf("%s: the resumed scan asked crt.sh again (%d requests)", name, hits.Load())
		}
	}
}

// TestSaveResumeStateKeepsEarlierPosition covers #109: a resumed target
// interrupted again before its scan reported progress, and a target the run
// never reached, keep their saved resume points; so does a target finished
// before the first interrupt, with its sources and zone transfer (#315).
func TestSaveResumeStateKeepsEarlierPosition(t *testing.T) {
	finished := resumeTarget{Domain: "c.example", Done: true, RootDone: 9, Processed: 9, Sources: map[string][]string{"ct": {"dev"}},
		AXFR: []string{"zt"}, AXFRServers: []string{"ns1.c.example"}, AXFRDone: true, Permute: &resumePass{RootDone: 4}}
	prev := &resumeState{Targets: []resumeTarget{
		{Domain: "a.example", RootDone: 40, Processed: 40, Stats: scan.Stats{NXDomain: 38}, Results: []output.Result{{Result: scan.Result{Subdomain: "x.a.example"}}}},
		{Domain: "b.example", RootDone: 7, Processed: 7, Permute: &resumePass{RootDone: 3}},
		finished,
	}}
	f := cliFlags{stateFile: filepath.Join(t.TempDir(), "state.json")}
	out := output.New(nil, false, output.FormatText)
	saveResumeState(&session{
		f: f, out: out, resume: prev,
		targets:      []string{"a.example", "b.example", "c.example"},
		status:       []report.Status{report.StatusInterrupted, report.StatusNotRun, report.StatusOK},
		entryDigests: []string{"d1", "", "d3"},
		results:      []targetResult{{}, {}, {done: true}},
		runs:         []resultLog{{names: []string{"x.a.example"}}, {}, {}},
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
	if c := st.Targets[2]; !reflect.DeepEqual(c, finished) {
		t.Errorf("finished target saved as %+v, want its earlier state %+v", c, finished)
	}
}

// TestSaveResumeStateKeepsFailedSources covers #237: a source that failed in
// the interrupted run is saved with no names, so the resumed run replays
// that instead of fetching it again; a fetch that now succeeded would insert
// names before later sources' and shift the saved resume position.
func TestSaveResumeStateKeepsFailedSources(t *testing.T) {
	f := cliFlags{stateFile: filepath.Join(t.TempDir(), "state.json")}
	saveResumeState(&session{
		f: f, out: output.New(nil, false, output.FormatText),
		targets:      []string{"a.example"},
		status:       []report.Status{report.StatusInterrupted},
		entryDigests: []string{"d1"},
		results: []targetResult{{done: true, sources: []targetSource{
			{Source: "ct", Err: "crt.sh: 502 Bad Gateway"},
			{Source: "wayback", Names: []string{"old-shop"}, Fetched: true},
		}}},
		runs: []resultLog{{}},
	})
	data, err := os.ReadFile(f.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	var st resumeState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	tg := &st.Targets[0]
	if names, ok := tg.sourceNames("ct"); !ok || len(names) != 0 {
		t.Errorf("failed ct source replays %v (saved %v), want no names and no new fetch", names, ok)
	}
	if names, ok := tg.sourceNames("wayback"); !ok || len(names) != 1 || names[0] != "old-shop" {
		t.Errorf("wayback replays %v (saved %v), want [old-shop]", names, ok)
	}
	if _, ok := tg.sourceNames("dns"); ok {
		t.Error("a source the run never asked reads as saved")
	}
}

// TestSaveResumeStateRetriesLookupsCutShort covers #299: a source lookup or
// zone transfer that failed before the target's scan started is not saved as
// final, so the resumed run tries it again; once the scan has started, in
// this run or the one it resumed, it stays as saved (#237).
func TestSaveResumeStateRetriesLookupsCutShort(t *testing.T) {
	sources := []targetSource{
		{Source: "ct", Err: "crt.sh: context canceled"},
		{Source: "wayback", Names: []string{"old-shop"}, Fetched: true},
	}
	axfr := targetAXFR{done: true}
	for name, tc := range map[string]struct {
		res    targetResult
		prev   *resumeState
		pinned bool
	}{
		"before the scan":          {targetResult{sources: sources, axfr: axfr}, nil, false},
		"scan started":             {targetResult{done: true, sources: sources, axfr: axfr}, nil, true},
		"resumed a started scan":   {targetResult{sources: sources, axfr: axfr}, &resumeState{Targets: []resumeTarget{{Domain: "a.example", RootDone: 5}}}, true},
		"resumed an unstarted one": {targetResult{sources: sources, axfr: axfr}, &resumeState{Targets: []resumeTarget{{Domain: "a.example"}}}, false},
	} {
		f := cliFlags{stateFile: filepath.Join(t.TempDir(), "state.json")}
		saveResumeState(&session{
			f: f, out: output.New(nil, false, output.FormatText), resume: tc.prev,
			targets:      []string{"a.example"},
			status:       []report.Status{report.StatusInterrupted},
			entryDigests: []string{"d1"},
			results:      []targetResult{tc.res},
			runs:         []resultLog{{}},
		})
		data, err := os.ReadFile(f.stateFile)
		if err != nil {
			t.Fatal(err)
		}
		var st resumeState
		if err := json.Unmarshal(data, &st); err != nil {
			t.Fatal(err)
		}
		tg := &st.Targets[0]
		if _, ok := tg.sourceNames("ct"); ok != tc.pinned {
			t.Errorf("%s: failed ct source saved as final = %v, want %v", name, ok, tc.pinned)
		}
		if names, ok := tg.sourceNames("wayback"); !ok || len(names) != 1 {
			t.Errorf("%s: wayback replays %v (saved %v), want [old-shop]", name, names, ok)
		}
		if tg.AXFRDone != tc.pinned {
			t.Errorf("%s: zone transfer saved as done = %v, want %v", name, tg.AXFRDone, tc.pinned)
		}
	}
}

// TestE2EResumeRefetchesInterruptedSource covers #299: an interrupt during a
// passive source's lookup, before the scan, leaves the source out of the
// state, so the resumed run asks it again and scans its names.
func TestE2EResumeRefetchesInterruptedSource(t *testing.T) {
	t.Parallel()
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.Name == "late.example.com" && q.Type == dnsmessage.TypeA {
			return dnstest.Reply{A: []string{"192.0.2.10"}}
		}
		return dnstest.NXDomain
	})
	signals := make(chan os.Signal, 1)
	var hits atomic.Int32
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			// The interrupt arrives while the first lookup is waiting.
			signals <- os.Interrupt
			select {
			case <-r.Context().Done():
			case <-time.After(30 * time.Second):
			}
			return
		}
		_, _ = w.Write([]byte(`[{"name_value": "late.example.com"}]`))
	}))
	defer ct.Close()
	urls := map[string]string{"ct": ct.URL + "/"}

	wl := writeFile(t, "wl.txt", "www\n")
	path := filepath.Join(t.TempDir(), "state.json")
	code, out := runCLIMergedWith(t, runArgs{sourceURLs: urls, signals: signals,
		args: append(localArgs("-ct", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-state", path, "-w", wl), "example.com")})
	if code != 130 {
		t.Fatalf("interrupted run: exit %d, want 130\n%s", code, out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no resume state saved: %v\n%s", err, out)
	}
	var st resumeState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.target("example.com").sourceNames("ct"); ok {
		t.Errorf("the interrupted lookup was saved as final: %s", data)
	}

	code, out = runCLIMergedWith(t, runArgs{sourceURLs: urls, args: []string{"-resume", path}})
	if code != 0 || !strings.Contains(out, "late.example.com") {
		t.Errorf("resumed run: exit %d, want late.example.com from a new lookup\n%s", code, out)
	}
	if hits.Load() < 2 {
		t.Errorf("the resumed run did not ask the source again (%d requests)", hits.Load())
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
		status:       []report.Status{report.StatusInterrupted},
		entryDigests: []string{"d1"},
		results: []targetResult{{
			done:        true,
			final:       scan.Event{Kind: scan.EventDone, Stats: scan.Stats{RootDone: 40}, Processed: 40, Total: 40},
			permutation: &permutationResult{candidates: 12, pass: targetResult{done: true, final: final}},
		}},
		runs: []resultLog{{}},
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

// TestSaveResumeStateMarksFinishedMainPass covers #358: a target stopped in
// its -permute pass is saved with its main pass finished, counted in full,
// since the resumed run does not scan it again.
func TestSaveResumeStateMarksFinishedMainPass(t *testing.T) {
	main := scan.Event{Kind: scan.EventDone, Stats: scan.Stats{RootDone: 40, NXDomain: 30, Repeat: scan.Repeat{NXDomain: 10, Processed: 10}},
		Processed: 40, Total: 40}
	f := cliFlags{stateFile: filepath.Join(t.TempDir(), "state.json")}
	saveResumeState(&session{
		f: f, out: output.New(nil, false, output.FormatText),
		targets:      []string{"a.example"},
		status:       []report.Status{report.StatusInterrupted},
		entryDigests: []string{"d1"},
		results:      []targetResult{{done: true, final: main, permutation: &permutationResult{candidates: 12}}},
		runs:         []resultLog{{}},
	})
	data, err := os.ReadFile(f.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	var st resumeState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	got := st.Targets[0]
	if got.Done || !got.MainDone {
		t.Errorf("done %v, main_done %v; want only the main pass finished", got.Done, got.MainDone)
	}
	if got.Processed != 40 || got.Stats.NXDomain != 30 || got.RootDone != 40 {
		t.Errorf("main pass saved as %d processed, %d NXDOMAIN, root_done %d; want it whole (40, 30, 40)", got.Processed, got.Stats.NXDomain, got.RootDone)
	}
}

// TestE2EResumePermuteSkipsFinishedMainPass covers #358: resuming a
// -recursive -permute scan stopped in its permutation pass does not scan the
// finished main pass again, which would re-expand every saved parent, and
// resumes in the same candidate list.
func TestE2EResumePermuteSkipsFinishedMainPass(t *testing.T) {
	t.Parallel()
	words := "api\ndev\nwww\nmail\nshop\nblog\n"
	wl := writeFile(t, "wl.txt", words)
	args := []string{"-simulate", "-seed", "5", "-hit-rate", "50", "-progress=false", "-format", "jsonl",
		"-permute", "-recursive", "-depth", "2", "-w", wl, "example.com"}
	code, ref := runCLI(t, "", args...)
	if code != 0 {
		t.Fatalf("reference run: exit %d", code)
	}
	refResults, _ := jsonlRecords(t, ref)
	// Leave one depth-2 name out of the saved main pass: re-expanding its
	// saved parent would find it again.
	var mainResults []output.Result
	child := ""
	for _, r := range refResults {
		if r.Permutation {
			continue
		}
		if child == "" && strings.Count(strings.TrimSuffix(r.Subdomain, ".example.com"), ".") == 1 {
			child = r.Subdomain
			continue
		}
		mainResults = append(mainResults, r)
	}
	if child == "" {
		t.Fatal("reference run found no depth-2 name; adjust the seed")
	}
	entries, _, _ := wordlist.Build(strings.Split(words, "\n"), "example.com")
	perms := candidatesFor("example.com", entries, mainPassNames(mainResults))
	if len(perms) < 2 {
		t.Fatalf("%d permutation candidates; adjust the seed", len(perms))
	}
	half := len(perms) / 2
	stopped := resumeTarget{Domain: "example.com", MainDone: true, RootDone: len(entries), Processed: int64(len(entries)),
		Results: mainResults, Permute: &resumePass{RootDone: half, Processed: int64(half)}}
	path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{stopped}})
	code, stdout, stderr := runCLIStreams(t, "-resume", path)
	if code != 0 {
		t.Fatalf("resume: exit %d\n%s", code, stderr)
	}
	if strings.Contains(stderr, "at wordlist entry") {
		t.Errorf("the finished main pass was scanned again:\n%s", stderr)
	}
	if want := fmt.Sprintf("at candidate %d of %d", half, len(perms)); !strings.Contains(stderr, want) {
		t.Errorf("permutation pass not resumed %q:\n%s", want, stderr)
	}
	if got, _ := jsonlRecords(t, stdout); resultNames(got)[child] {
		t.Errorf("%s was looked up again by the main pass", child)
	}
}

// TestE2EPermuteRecursive covers #111: -permute with -recursive runs the
// permutation pass one level deep, so no name is built from a candidate
// under another candidate and the pass is not refused.
func TestE2EPermuteRecursive(t *testing.T) {
	t.Parallel()
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

// TestResumeStateKeys pins the state file's JSON keys (#331): renaming a
// field of resumeState, or of a type it stores such as scan.Stats, changes
// the format a newer binary reads back. A change here needs a
// resumeStateVersion bump, or a tag that keeps the old key.
func TestResumeStateKeys(t *testing.T) {
	var stats scan.Stats
	sv := reflect.ValueOf(&stats).Elem()
	for i := range sv.NumField() {
		switch v := sv.Field(i); v.Kind() {
		case reflect.Int64:
			v.SetInt(1)
		case reflect.Bool:
			v.SetBool(true)
		case reflect.Slice:
			setOne(v)
		case reflect.Struct:
			v.Field(0).SetInt(1) // Repeat: not saved (json:"-")
		default:
			t.Fatalf("scan.Stats.%s: unhandled kind %s", sv.Type().Field(i).Name, v.Kind())
		}
	}
	st := resumeState{
		Version:  resumeStateVersion,
		Args:     []string{"example.com"},
		Inputs:   map[string]string{"words.txt": "00"},
		Settings: map[string]string{"t": "100"},
		Targets: []resumeTarget{{
			Domain: "example.com", Done: true, RootDone: 1, Stats: stats, Processed: 1, Total: 1,
			Results: []output.Result{{
				Result: scan.Result{Subdomain: "a.example.com", Records: []dns.Record{{Type: "A", Value: "192.0.2.1"}},
					Simulated: true, Takeover: "dangling", Internal: "private"},
				Change: "changed", PreviousRecords: []dns.Record{{Type: "A", Value: "192.0.2.2"}},
				Permutation: true, Sources: []string{"wordlist"},
			}},
			Pending: []savedPending{{Name: "b.example.com", Outcome: "timeout"}},
			Entries: "00",
			Permute: &resumePass{RootDone: 1, Stats: stats, Processed: 1, Total: 1, Found: 1,
				Pending: []savedPending{{Name: "c.example.com", Outcome: "refused"}}},
			CT:          []string{"a"},
			CTFetched:   true,
			Sources:     map[string][]string{"crtsh": {"a"}},
			AXFR:        []string{"a"},
			AXFRServers: []string{"ns"},
			AXFRDone:    true,
			Denial:      "nsec",
		}},
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	// Keys of the maps that hold user data (file names, settings, sources)
	// are values, not format; only their position is recorded.
	dataMaps := map[string]bool{"inputs": true, "settings": true, "targets.sources": true}
	var keys []string
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch v := v.(type) {
		case map[string]any:
			if dataMaps[path] {
				keys = append(keys, path+".*")
				return
			}
			for k, e := range v {
				p := k
				if path != "" {
					p = path + "." + k
				}
				keys = append(keys, p)
				walk(p, e)
			}
		case []any:
			for _, e := range v {
				walk(path, e)
			}
		}
	}
	walk("", doc)
	slices.Sort(keys)
	keys = slices.Compact(keys)
	want := strings.Fields(`args inputs inputs.* settings settings.* version
		targets targets.axfr targets.axfr_done targets.axfr_servers targets.ct targets.ct_fetched
		targets.denial targets.domain targets.done targets.entries targets.processed targets.root_done
		targets.sources targets.sources.* targets.total targets.stats
		targets.pending targets.pending.name targets.pending.outcome
		targets.permute targets.permute.found targets.permute.processed targets.permute.root_done
		targets.permute.total targets.permute.stats
		targets.permute.pending targets.permute.pending.name targets.permute.pending.outcome
		targets.results targets.results.change targets.results.internal_address targets.results.permutation
		targets.results.previous_records targets.results.previous_records.type targets.results.previous_records.value
		targets.results.records targets.results.records.type targets.results.records.value
		targets.results.simulated targets.results.sources targets.results.subdomain targets.results.takeover_candidate`)
	// scan.Stats is stored twice, for the target and for its -permute pass.
	statsKeys := strings.Fields(`Aborted Confirmed Excluded Expired FinalRate Fingerprint Fingerprint.type
		Fingerprint.value Found Inconclusive Internal NXDomain Other Partial PoolHits QueriesSent RateBackoffs
		Recovered Refused Retried RootDone Skipped Takeover Timeout Unconfirmed Wildcard WildcardFiltered`)
	for _, prefix := range []string{"targets.stats.", "targets.permute.stats."} {
		for _, k := range statsKeys {
			want = append(want, prefix+k)
		}
	}
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Errorf("resume state keys changed; bump resumeStateVersion or keep the old keys.\ngot:  %q\nwant: %q", keys, want)
	}
}

// setOne sets a scan.Stats slice field to one element.
func setOne(v reflect.Value) {
	switch v.Type().Elem() {
	case reflect.TypeFor[string]():
		v.Set(reflect.ValueOf([]string{"a.example.com"}))
	case reflect.TypeFor[dns.Record]():
		v.Set(reflect.ValueOf([]dns.Record{{Type: "A", Value: "192.0.2.1"}}))
	default:
		v.Set(reflect.Append(reflect.MakeSlice(v.Type(), 0, 1), reflect.New(v.Type().Elem()).Elem()))
	}
}

// TestMergeStatsCoversEveryField is the drift guard of #162: a field added to
// scan.Stats that mergeStats drops fails here. Each field set in either the
// saved or the resumed run must survive the merge; RootDone, and Aborted and
// Expired (how the scan ended, #294), are taken from the resumed run alone.
func TestMergeStatsCoversEveryField(t *testing.T) {
	zero := mergeStats(scan.Stats{}, scan.Stats{})
	st := reflect.TypeOf(scan.Stats{})
	for i := range st.NumField() {
		name := st.Field(i).Name
		for _, side := range []string{"saved", "resumed"} {
			// The saved part's Repeat was taken off it (withoutRepeat), and
			// its Pending handed to the resumed part (handOverPending).
			if side == "saved" && (name == "RootDone" || name == "Aborted" || name == "Expired" || name == "Repeat" || name == "Pending") {
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
				setOne(v)
			case reflect.Struct:
				v.Field(0).SetInt(1)
			default:
				t.Fatalf("scan.Stats.%s: unhandled kind %s", name, v.Kind())
			}
			if got := mergeStats(a, b); reflect.DeepEqual(got, zero) {
				t.Errorf("mergeStats drops scan.Stats.%s from the %s run", name, side)
			}
		}
	}
}
