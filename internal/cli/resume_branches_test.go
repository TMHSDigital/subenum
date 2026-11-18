package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// The tests in this file cover resume branches that had no test (#401).

// hostWords is a wordlist of n names, host0 to host<n-1>.
func hostWords(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "host%d\n", i)
	}
	return b.String()
}

// readState reads a saved resume state.
func readState(t *testing.T, path string) resumeState {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no resume state: %v", err)
	}
	var st resumeState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// readSummary reads a -stats report.
func readSummary(t *testing.T, path string) output.Summary {
	t.Helper()
	var s output.Summary
	if data, err := os.ReadFile(path); err != nil || json.Unmarshal(data, &s) != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return s
}

// resumeToEnd resumes the state at path until a run removes it, and returns
// the last run's exit code and output.
func resumeToEnd(t *testing.T, path string, extra ...string) (int, string) {
	t.Helper()
	for i := 0; i < 30; i++ {
		code, out := runCLIMerged(t, append([]string{"-resume", path}, extra...)...)
		if _, err := os.Stat(path); err != nil {
			return code, out // the run that finished removed its state
		}
		if code != 0 && code != 130 {
			t.Fatalf("resumed run %d: exit %d\n%s", i, code, out)
		}
	}
	t.Fatal("the scan did not finish in 30 resumed runs")
	return 0, ""
}

// TestE2EResumePinsSimulationSeed covers #401: a -simulate run given no
// -seed saves its random seed first in the replayed arguments, so resuming
// it simulates the same answers as one uninterrupted run with that seed.
func TestE2EResumePinsSimulationSeed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	state, results := filepath.Join(dir, "state.json"), filepath.Join(dir, "results.jsonl")
	base := []string{"-simulate", "-hit-rate", "50", "-progress=false", "-format", "jsonl", "-w", writeFile(t, "wl.txt", hostWords(120))}
	// -rate 50 with 120 words needs about 2.4 s; the budget is 400 ms.
	code, out := runCLIMerged(t, append(slices.Clone(base), "-t", "2", "-rate", "50", "-max-duration", "400ms",
		"-state", state, "-o", results, "example.com")...)
	if code != 0 {
		t.Fatalf("stopped run: exit %d\n%s", code, out)
	}
	st := readState(t, state)
	if len(st.Args) < 2 || st.Args[0] != "-seed" {
		t.Fatalf("saved args %q, want them to start with -seed <n>", st.Args)
	}
	seed, err := strconv.ParseUint(st.Args[1], 10, 64)
	if err != nil || seed == 0 {
		t.Fatalf("saved seed %q (err %v), want the run's nonzero seed", st.Args[1], err)
	}
	if !strings.Contains(out, "seed "+st.Args[1]) {
		t.Errorf("the saved seed %s is not the one the run used:\n%s", st.Args[1], out)
	}
	if code, out := resumeToEnd(t, state); code != 0 {
		t.Fatalf("last resumed run: exit %d\n%s", code, out)
	}
	data, err := os.ReadFile(results)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := jsonlRecords(t, string(data))

	code, ref := runCLI(t, "", append(slices.Clone(base), "-seed", st.Args[1], "example.com")...)
	if code != 0 {
		t.Fatalf("reference run: exit %d", code)
	}
	want, _ := jsonlRecords(t, ref)
	if len(want) == 0 {
		t.Fatal("the reference run found nothing; adjust -hit-rate")
	}
	if !maps.Equal(resultNames(got), resultNames(want)) {
		t.Errorf("resumed scan found %d names, one run with -seed %s %d", len(resultNames(got)), st.Args[1], len(resultNames(want)))
	}
}

// TestE2EResumeBuiltinLab covers #354 and #401: a stopped run of a built-in
// lab named as such saves a state whose inputs do not list the lab name,
// which is no file, and resuming it succeeds.
func TestE2EResumeBuiltinLab(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	wl := writeFile(t, "wl.txt", hostWords(120))
	// lab2 is a wildcard zone, which -force scans anyway.
	args := append([]string{"-simulate-zone", "lab2", "-force", "-progress=false", "-w", wl, "-t", "2", "-rate", "50",
		"-max-duration", "1s", "-state", state}, labTimingArgs...)
	code, out := runCLIMerged(t, append(args, "lab.example")...)
	if code != 0 {
		t.Fatalf("stopped run: exit %d\n%s", code, out)
	}
	st := readState(t, state)
	if _, ok := st.Inputs["lab2"]; ok {
		t.Errorf("saved inputs %v list the built-in lab", st.Inputs)
	}
	if _, ok := st.Inputs[wl]; !ok {
		t.Errorf("saved inputs %v lack the wordlist", st.Inputs)
	}
	if code, out := runCLIMerged(t, "-resume", state, "-rate", "0", "-max-duration", "1h"); code != 0 {
		t.Fatalf("resumed run: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Errorf("the finished run's state file was not removed (err %v)", err)
	}
}

// TestE2EStdinWordlistSavesNoState covers #401: a run whose wordlist came
// from stdin cannot be replayed, so a stop saves no state, says so, and
// exits as a run that saved one would.
func TestE2EStdinWordlistSavesNoState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	words := hostWords(120)
	// -rate 50 with 120 words needs about 2.4 s; the budget is 400 ms.
	stop := []string{"-simulate", "-seed", "3", "-progress=false", "-t", "2", "-rate", "50", "-max-duration", "400ms"}

	saved := filepath.Join(dir, "saved.json")
	wantCode, out := runCLIMerged(t, append(slices.Clone(stop), "-state", saved, "-w", writeFile(t, "wl.txt", words), "example.com")...)
	if _, err := os.Stat(saved); err != nil {
		t.Fatalf("the run with a -w file (exit %d) saved no state: %v\n%s", wantCode, err, out)
	}

	state := filepath.Join(dir, "state.json")
	var stdout, stderr bytes.Buffer
	code := runWith(runArgs{args: append(slices.Clone(stop), "-state", state, "-w", "-", "example.com"),
		stdin: strings.NewReader(words), stdout: &stdout, stderr: &stderr})
	if code != wantCode {
		t.Errorf("exit %d, want %d as for the run that saved its state\n%s", code, wantCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Not saving resume state") {
		t.Errorf("stderr does not say the state is not saved:\n%s", stderr.String())
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Errorf("a state file was written for a stdin wordlist (err %v)", err)
	}
}

// TestE2EResumeRecursiveRepeatedInconclusive covers #341 and #401: a
// -recursive run stopped at depth 2 leaves out of its saved inconclusive
// list the depth-2 names the resumed run looks up again, as it re-expands
// every saved parent. A name that answers on resume is then not listed, and
// none is listed twice.
func TestE2EResumeRecursiveRepeatedInconclusive(t *testing.T) {
	t.Parallel()
	const flaky = "c.a.example.test"
	words := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	children := map[string]bool{}
	for _, w := range words {
		children[w+".a.example.test"] = true
	}
	signals := make(chan os.Signal, 1)
	var seen, stopped atomic.Bool
	var once sync.Once
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Type != dnsmessage.TypeA:
		case q.Name == "example.test" || q.Name == "a.example.test":
			return dnstest.Reply{A: []string{"192.0.2.1"}}
		case q.Name == flaky:
			if !stopped.Load() {
				seen.Store(true)
				return dnstest.Dropped // a timeout, until the run is stopped
			}
		case children[q.Name] && seen.Load():
			// One worker: the timeout has been counted before this query.
			once.Do(func() {
				stopped.Store(true)
				signals <- os.Interrupt
			})
		}
		return dnstest.NXDomain
	})
	dir := t.TempDir()
	state, incon := filepath.Join(dir, "state.json"), filepath.Join(dir, "incon.txt")
	code, out := runCLIMergedWith(t, runArgs{signals: signals, args: []string{"-dns-server", srv.Addr, "-type", "A", "-progress=false",
		"-t", "1", "-timeout", "1000", "-attempts", "1", "-recursive", "-depth", "2", "-inconclusive", incon,
		"-state", state, "-w", writeFile(t, "wl.txt", strings.Join(words, "\n")+"\n"), "example.test"}})
	if code != 130 {
		t.Fatalf("stopped run: exit %d, want 130\n%s", code, out)
	}
	if !stopped.Load() {
		t.Fatalf("the run was not stopped at depth 2\n%s", out)
	}
	st := readState(t, state)
	if len(st.Targets) != 1 || st.Targets[0].Done {
		t.Fatalf("saved targets %+v, want one stopped", st.Targets)
	}
	if slices.Contains(st.Targets[0].Stats.Inconclusive, flaky) {
		t.Errorf("saved inconclusive names %q keep %s, which the resumed run looks up again", st.Targets[0].Stats.Inconclusive, flaky)
	}

	if code, out := runCLIMerged(t, "-resume", state); code != 0 {
		t.Fatalf("resumed run: exit %d\n%s", code, out)
	}
	data, err := os.ReadFile(incon)
	if err != nil {
		t.Fatal(err)
	}
	listed := strings.Fields(string(data))
	if slices.Contains(listed, flaky) {
		t.Errorf("%s answered on resume but is still listed inconclusive:\n%s", flaky, data)
	}
	if sorted := slices.Compact(slices.Sorted(slices.Values(listed))); len(sorted) != len(listed) {
		t.Errorf("a name is listed twice:\n%s", data)
	}
}

// TestE2EResumeKeepsRefusedPriorOutcome covers #315 and #401: a name the
// stopped run left for its retry pass as refused is retried as refused, so
// once it answers its refusal is taken off the refused count, not another.
func TestE2EResumeKeepsRefusedPriorOutcome(t *testing.T) {
	t.Parallel()
	stats := filepath.Join(t.TempDir(), "run.json")
	words := "www\napi\n"
	entries, _, _ := wordlist.Build(strings.Split(words, "\n"), "example.com")
	args := []string{"-simulate", "-seed", "3", "-hit-rate", "100", "-progress=false", "-retry-inconclusive", "-stats", stats,
		"-w", writeFile(t, "wl.txt", words), "example.com"}
	path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{{
		Domain: "example.com", RootDone: len(entries), Processed: int64(len(entries)), Total: int64(len(entries)),
		Results: []output.Result{{Result: scan.Result{Subdomain: "www.example.com"}}},
		Stats:   scan.Stats{RootDone: int64(len(entries)), Found: 1, Refused: 1},
		Pending: []savedPending{{Name: "api.example.com", Outcome: "refused"}},
	}}})
	if code, out := runCLIMerged(t, "-resume", path); code != 0 {
		t.Fatalf("resumed run: exit %d\n%s", code, out)
	}
	tg := readSummary(t, stats).Targets
	if len(tg) != 1 {
		t.Fatalf("%d targets in the report", len(tg))
	}
	if tg[0].Retried != 1 || tg[0].Recovered != 1 {
		t.Fatalf("retried %d, recovered %d; want the refused name retried and answered", tg[0].Retried, tg[0].Recovered)
	}
	if o := tg[0].Outcomes; o.Refused != 0 || o.Other != 0 || o.Timeout != 0 {
		t.Errorf("outcomes %+v; want the refusal moved off the refused count and nothing else changed", o)
	}
}

// permuteServer answers the main-pass words api, dev and www of example.test,
// and the permutation candidates by answer, which gets each candidate's full
// name; every other name is NXDOMAIN. It returns the candidates too.
func permuteServer(t *testing.T, words string, answer func(name string) dnstest.Reply) (*dnstest.Server, []string) {
	t.Helper()
	found := []string{"api.example.test", "dev.example.test", "www.example.test"}
	entries, _, _ := wordlist.Build(strings.Split(words, "\n"), "example.test")
	cands := candidatesFor("example.test", entries, found)
	isCand := map[string]bool{}
	for _, c := range cands {
		isCand[c+".example.test"] = true
	}
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Type != dnsmessage.TypeA:
		case q.Name == "example.test" || slices.Contains(found, q.Name):
			return dnstest.Reply{A: []string{"192.0.2.1"}}
		case isCand[q.Name]:
			return answer(q.Name)
		}
		return dnstest.NXDomain
	})
	return srv, cands
}

// TestE2EResumeInPermutePassCountsOnce covers #156 and #401: a scan stopped
// in its -permute pass and resumed reports the found and processed counts of
// one uninterrupted run, the names the resumed pass finds again included.
func TestE2EResumeInPermutePassCountsOnce(t *testing.T) {
	t.Parallel()
	const words = "api\ndev\nwww\nmail\nshop\nblog\n"
	signals := make(chan os.Signal, 1)
	var armed atomic.Bool
	var once sync.Once
	var stopAt string
	srv, cands := permuteServer(t, words, func(name string) dnstest.Reply {
		if armed.Load() && name == stopAt {
			once.Do(func() { signals <- os.Interrupt })
		}
		if len(name)%2 == 0 {
			return dnstest.Reply{A: []string{"192.0.2.2"}}
		}
		return dnstest.NXDomain
	})
	if len(cands) < 20 {
		t.Fatalf("%d permutation candidates; want at least 20", len(cands))
	}
	stopAt = cands[len(cands)/2] + ".example.test"
	dir := t.TempDir()
	wl := writeFile(t, "wl.txt", words)
	args := func(stats string, extra ...string) []string {
		return append([]string{"-dns-server", srv.Addr, "-type", "A", "-progress=false", "-t", "4", "-permute",
			"-stats", stats, "-w", wl}, append(extra, "example.test")...)
	}
	full := filepath.Join(dir, "full.json")
	if code, out := runCLIMerged(t, args(full)...); code != 0 {
		t.Fatalf("uninterrupted run: exit %d\n%s", code, out)
	}
	want := readSummary(t, full).Targets[0]
	if want.Permutation == nil || want.Permutation.Found == 0 {
		t.Fatalf("uninterrupted run: permutation %+v, want names found", want.Permutation)
	}

	armed.Store(true)
	stats, state := filepath.Join(dir, "stats.json"), filepath.Join(dir, "state.json")
	code, out := runCLIMergedWith(t, runArgs{signals: signals, args: args(stats, "-state", state)})
	if code != 130 {
		t.Fatalf("stopped run: exit %d, want 130\n%s", code, out)
	}
	armed.Store(false)
	st := readState(t, state)
	if len(st.Targets) != 1 || !st.Targets[0].MainDone || st.Targets[0].Permute == nil {
		t.Fatalf("saved targets %+v, want one stopped in its permutation pass", st.Targets)
	}
	if code, out := runCLIMerged(t, "-resume", state); code != 0 {
		t.Fatalf("resumed run: exit %d\n%s", code, out)
	}
	got := readSummary(t, stats).Targets[0]
	if got.Found != want.Found || got.Processed != want.Processed || got.Permutation == nil ||
		got.Permutation.Found != want.Permutation.Found || got.Permutation.Processed != want.Permutation.Processed {
		t.Errorf("resumed: found %d, processed %d, permutation %+v; want found %d, processed %d, permutation %+v as uninterrupted",
			got.Found, got.Processed, got.Permutation, want.Found, want.Processed, want.Permutation)
	}
}

// TestE2EPermutePassAbortFailsTarget covers #401: when the reliability guard
// aborts the -permute pass, the run exits non-zero and reports the target
// failed, as an aborted main pass does.
func TestE2EPermutePassAbortFailsTarget(t *testing.T) {
	t.Parallel()
	const words = "api\ndev\nwww\nmail\n"
	srv, cands := permuteServer(t, words, func(string) dnstest.Reply { return dnstest.Refused })
	if len(cands) < 250 {
		t.Fatalf("%d permutation candidates; the guard needs well over 200", len(cands))
	}
	stats := filepath.Join(t.TempDir(), "run.json")
	// The server answers at once, so the long timeout costs nothing (#289).
	code, out := runCLIMerged(t, "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-t", "4", "-timeout", "10000",
		"-attempts", "1", "-permute", "-stats", stats, "-state", filepath.Join(t.TempDir(), "state.json"),
		"-w", writeFile(t, "wl.txt", words), "example.test")
	if code == 0 {
		t.Fatalf("exit 0 after the permutation pass was aborted\n%s", out)
	}
	tg := readSummary(t, stats).Targets
	if len(tg) != 1 || tg[0].Status != "failed" {
		t.Fatalf("targets %+v, want the one target failed\n%s", tg, out)
	}
	if tg[0].Permutation == nil || tg[0].Permutation.Processed >= int64(len(cands)) {
		t.Errorf("permutation %+v, want the pass stopped before its %d candidates", tg[0].Permutation, len(cands))
	}
}

// TestE2EPermutePassTimeoutListedInconclusive covers #401: a permutation
// candidate that times out is written to the -inconclusive file.
func TestE2EPermutePassTimeoutListedInconclusive(t *testing.T) {
	t.Parallel()
	const words = "api\ndev\nwww\n"
	var flaky atomic.Value
	srv, cands := permuteServer(t, words, func(name string) dnstest.Reply {
		if name == flaky.Load() {
			return dnstest.Dropped
		}
		return dnstest.NXDomain
	})
	if len(cands) == 0 {
		t.Fatal("no permutation candidates")
	}
	name := cands[0] + ".example.test"
	flaky.Store(name)
	incon := filepath.Join(t.TempDir(), "incon.txt")
	code, out := runCLIMerged(t, "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-t", "4", "-timeout", "500",
		"-attempts", "1", "-permute", "-inconclusive", incon, "-w", writeFile(t, "wl.txt", words), "example.test")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	data, err := os.ReadFile(incon)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(strings.Fields(string(data)), name) {
		t.Errorf("-inconclusive lacks the permutation candidate %s that timed out:\n%s", name, data)
	}
}
