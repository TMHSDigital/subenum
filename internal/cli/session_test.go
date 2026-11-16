package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// TestE2EResumeSkipsFinishedTarget covers #304: resuming a -dL run restores a
// target that finished before the interrupt without scanning it again, and
// continues the interrupted one from its saved position.
func TestE2EResumeSkipsFinishedTarget(t *testing.T) {
	t.Parallel()
	wl := writeFile(t, "wl.txt", e2eWords)
	dl := writeFile(t, "domains.txt", "a.example\nb.example\n")
	args := []string{"-simulate", "-seed", "5", "-hit-rate", "100", "-t", "1", "-progress=false", "-format", "jsonl", "-w", wl, "-dL", dl}
	entries, _, _ := wordlist.Build(strings.Split(e2eWords, "\n"), "a.example")
	total := int64(len(entries))
	saved := func(domain string, n int) []output.Result {
		var results []output.Result
		for _, e := range entries[:n] {
			results = append(results, output.Result{Result: scan.Result{Subdomain: e + "." + domain}})
		}
		return results
	}
	// a.example is finished with three names, fewer than a scan at -hit-rate
	// 100 gives, and its saved position is left at the start: only done says
	// it needs no scan, and a second scan of it would show as extra names.
	path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{
		{Domain: "a.example", Done: true, Processed: total, Total: total,
			Results: saved("a.example", 3), Stats: scan.Stats{Found: 3, NXDomain: total - 3}},
		{Domain: "b.example", RootDone: 2, Processed: 2, Total: total,
			Results: saved("b.example", 2), Stats: scan.Stats{Found: 2}},
	}})
	code, out, stderr := runCLIStreams(t, "-resume", path)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	results, summary := jsonlRecords(t, out)
	seen := map[string]int{}
	for _, r := range results {
		seen[r.Subdomain]++
	}
	want := map[string]int{}
	for _, r := range saved("a.example", 3) {
		want[r.Subdomain] = 1
	}
	for _, r := range saved("b.example", len(entries)) {
		want[r.Subdomain] = 1
	}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Errorf("results = %v, want each of %v once", seen, want)
	}
	for _, msg := range []string{
		"a.example was finished before the run stopped; 3 results restored",
		fmt.Sprintf("Resuming b.example at wordlist entry 2 of %d (2 results restored)", len(entries)),
	} {
		if !strings.Contains(stderr, msg) {
			t.Errorf("stderr lacks %q:\n%s", msg, stderr)
		}
	}
	if strings.Contains(stderr, "Resuming a.example") {
		t.Errorf("the finished target was scanned again:\n%s", stderr)
	}
	if len(summary.Targets) != 2 {
		t.Fatalf("summary has %d targets, want 2", len(summary.Targets))
	}
	if a := summary.Targets[0]; a.Status != "ok" || a.Found != 3 || a.Processed != total {
		t.Errorf("a.example: status %q, found %d, processed %d; want ok, 3, %d", a.Status, a.Found, a.Processed, total)
	}
	if b := summary.Targets[1]; b.Status != "ok" || b.Found != total || b.Processed != total {
		t.Errorf("b.example: status %q, found %d, processed %d; want ok, %d, %d", b.Status, b.Found, b.Processed, total, total)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the finished run's state file was not removed (err %v)", err)
	}
}

// TestE2EResolverAbortSkipsRemainingTargets covers #304: when the
// reliability guard aborts one target of a -dL run, the targets after it are
// skipped without a query, and the run fails; with -no-abort every target is
// scanned.
func TestE2EResolverAbortSkipsRemainingTargets(t *testing.T) {
	t.Parallel()
	domains := []string{"one.example", "two.example", "three.example"}
	// Enough failing names for the guard to act on.
	var words strings.Builder
	for i := 0; i < 250; i++ {
		fmt.Fprintf(&words, "host%d\n", i)
	}
	wl := writeFile(t, "wl.txt", words.String())
	dl := writeFile(t, "domains.txt", strings.Join(domains, "\n")+"\n")

	// run scans the list against a resolver that answers for each apex and
	// fails every wordlist name. It returns the exit code, stderr, each
	// target's status and error from the -stats report, and the number of
	// queries the server saw per target.
	run := func(t *testing.T, extra ...string) (int, string, []string, []string, map[string]int) {
		t.Helper()
		var mu sync.Mutex
		queries := map[string]int{}
		srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
			for _, d := range domains {
				if q.Name != d && !strings.HasSuffix(q.Name, "."+d) {
					continue
				}
				mu.Lock()
				queries[d]++
				mu.Unlock()
				switch {
				case q.Name != d && strings.HasPrefix(q.Name, "host"):
					return dnstest.ServFail
				case q.Name != d:
					return dnstest.NXDomain
				case q.Type == dnsmessage.TypeA:
					return dnstest.Reply{A: []string{"192.0.2.10"}}
				}
				return dnstest.Reply{}
			}
			return dnstest.NXDomain
		})
		dir := t.TempDir()
		stats := filepath.Join(dir, "run.json")
		args := append(localArgs("-dns-server", srv.Addr, "-type", "A", "-progress=false",
			"-state", filepath.Join(dir, "state.json"), "-stats", stats, "-w", wl, "-dL", dl), extra...)
		code, _, stderr := runCLIStreams(t, args...)
		var summary output.Summary
		if data, err := os.ReadFile(stats); err != nil || json.Unmarshal(data, &summary) != nil {
			t.Fatalf("reading -stats: %v\n%s", err, stderr)
		}
		var status, errs []string
		for _, tg := range summary.Targets {
			status = append(status, tg.Status)
			errs = append(errs, tg.Error)
		}
		mu.Lock()
		defer mu.Unlock()
		return code, stderr, status, errs, queries
	}

	t.Run("abort", func(t *testing.T) {
		t.Parallel()
		code, stderr, status, _, queries := run(t)
		if code != exitFailure {
			t.Errorf("exit %d, want %d (every target failed or was skipped)\n%s", code, exitFailure, stderr)
		}
		if !strings.Contains(stderr, "skipping the 2 remaining targets") {
			t.Errorf("stderr does not say the remaining targets were skipped:\n%s", stderr)
		}
		if got := strings.Join(status, ","); got != "failed,skipped,skipped" {
			t.Errorf("target statuses = %s, want failed,skipped,skipped", got)
		}
		if queries["one.example"] == 0 || queries["two.example"] != 0 || queries["three.example"] != 0 {
			t.Errorf("queries per target = %v, want some for one.example only", queries)
		}
	})
	t.Run("no-abort", func(t *testing.T) {
		t.Parallel()
		code, stderr, status, errs, queries := run(t, "-no-abort")
		if code != exitOK {
			t.Errorf("exit %d, want %d\n%s", code, exitOK, stderr)
		}
		// The guard's warning is a warning, not an error, and a target that
		// went on to finish does not report it as its error (#308).
		if !strings.Contains(stderr, "Warning: ") || strings.Contains(stderr, "Error: ") {
			t.Errorf("stderr shows the -no-abort warning as an error, or not at all:\n%s", stderr)
		}
		if got := strings.Join(errs, ""); got != "" {
			t.Errorf("target errors %q, want none", errs)
		}
		if strings.Contains(stderr, "remaining targets") {
			t.Errorf("targets were skipped under -no-abort:\n%s", stderr)
		}
		if got := strings.Join(status, ","); got != "ok,ok,ok" {
			t.Errorf("target statuses = %s, want ok,ok,ok", got)
		}
		for _, d := range domains {
			if queries[d] == 0 {
				t.Errorf("%s got no queries under -no-abort: %v", d, queries)
			}
		}
	})
}

// TestE2EReportFileWriteErrors covers #304: a -stats, -sarif or -inconclusive
// file that cannot be written is reported and fails the run, after the
// results were printed.
func TestE2EReportFileWriteErrors(t *testing.T) {
	t.Parallel()
	wl := writeFile(t, "wl.txt", e2eWords)
	for _, flag := range []string{"-stats", "-sarif", "-inconclusive"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			// A directory cannot be written as a file.
			code, out, stderr := runCLIStreams(t, "-simulate", "-hit-rate", "100", "-progress=false",
				"-w", wl, flag, t.TempDir(), "example.com")
			if code != exitFailure {
				t.Errorf("exit %d, want %d", code, exitFailure)
			}
			if want := "writing " + flag + " file"; strings.Count(stderr, want) != 1 {
				t.Errorf("stderr should have %q once:\n%s", want, stderr)
			}
			if got := len(strings.Fields(out)); got != 6 || !strings.Contains(out, "www.example.com") {
				t.Errorf("results were not printed in full (%d names):\n%s", got, out)
			}
		})
	}
}

// TestE2EOutputFileCommitFailure covers #304 (and #30): when the finished
// results cannot replace the -o path, the error is printed once, the run
// exits 1 and no temporary file is left.
func TestE2EOutputFileCommitFailure(t *testing.T) {
	t.Parallel()
	wl := writeFile(t, "wl.txt", e2eWords)
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.txt")
	// The path becomes a directory once the scan is under way, after the
	// temporary file beside it was opened.
	var mkdirErr error
	stdout := &lineTrigger{n: 1, fire: func() { mkdirErr = os.Mkdir(outPath, 0o700) }}
	var stderr lockedBuffer
	code := runWith(runArgs{
		args:  []string{"-simulate", "-hit-rate", "100", "-t", "1", "-progress=false", "-w", wl, "-o", outPath, "example.com"},
		stdin: strings.NewReader(""), stdout: stdout, stderr: &stderr,
	})
	if mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	if fi, err := os.Stat(outPath); err != nil || !fi.IsDir() {
		t.Fatalf("the -o path was not replaced by a directory during the scan (err %v)", err)
	}
	if code != exitFailure {
		t.Errorf("exit %d, want %d", code, exitFailure)
	}
	if got := strings.Count(stderr.String(), "writing output file"); got != 1 {
		t.Errorf("\"writing output file\" printed %d times, want once:\n%s", got, stderr.String())
	}
	if left, _ := os.ReadDir(dir); len(left) != 1 {
		t.Errorf("files left beside the -o path: %v", left)
	}
}

// TestE2ESeedsImplyPermute covers #304: -seeds alone turns the permutation
// pass on, and its candidates come from the seed names, here one that is not
// in the wordlist.
func TestE2ESeedsImplyPermute(t *testing.T) {
	t.Parallel()
	wl := writeFile(t, "wl.txt", "www\nmail\n")
	seeds := writeFile(t, "prev.jsonl", `{"subdomain":"api.example.com"}`+"\n")
	args := []string{"-simulate", "-hit-rate", "100", "-progress=false", "-format", "jsonl", "-w", wl}

	code, out := runCLI(t, "", append(args, "example.com")...)
	if code != 0 {
		t.Fatalf("without -seeds: exit %d", code)
	}
	if _, summary := jsonlRecords(t, out); len(summary.Targets) != 1 || summary.Targets[0].Permutation != nil {
		t.Fatalf("without -seeds: summary targets = %+v, want one without a permutation pass", summary.Targets)
	}

	code, out = runCLI(t, "", append(args, "-seeds", seeds, "example.com")...)
	if code != 0 {
		t.Fatalf("with -seeds: exit %d", code)
	}
	_, summary := jsonlRecords(t, out)
	if len(summary.Targets) != 1 || summary.Targets[0].Permutation == nil {
		t.Fatalf("with -seeds: summary targets = %+v, want a permutation pass", summary.Targets)
	}
	p := summary.Targets[0].Permutation
	// The pass's seeds are the two names the main pass found and the one
	// from the file.
	entries, found := []string{"www", "mail"}, []string{"www.example.com", "mail.example.com"}
	without := candidatesFor("example.com", entries, found)
	want := candidatesFor("example.com", entries, append(found, "api.example.com"))
	if len(want) <= len(without) {
		t.Fatalf("api adds no permutation candidates (%d with it, %d without); the test needs another seed", len(want), len(without))
	}
	if p.Seeds != 3 || p.Candidates != len(want) || p.Processed != int64(len(want)) {
		t.Errorf("permutation = %+v, want 3 seeds and %d candidates, all processed", *p, len(want))
	}
}
