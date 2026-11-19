package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/output"
	"golang.org/x/net/dns/dnsmessage"
)

// seenResults decodes a JSONL results file's results by name.
func seenResults(t *testing.T, data string) map[string]output.Result {
	t.Helper()
	out := map[string]output.Result{}
	for line := range strings.SplitSeq(strings.TrimSpace(data), "\n") {
		var r struct {
			Type string `json:"type"`
			output.Result
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("not JSONL: %q", line)
		}
		if r.Type != "summary" {
			out[r.Subdomain] = r.Result
		}
	}
	return out
}

// TestE2EFirstAndLastSeen covers #420 end to end with an injected clock: a
// real run dates its results, a run that diffs against it keeps the earlier
// first_seen of names found again and reports a removed name with the
// baseline's dates, and subenum diff copies them through.
func TestE2EFirstAndLastSeen(t *testing.T) {
	t.Parallel()
	var oldGone atomic.Bool
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		live := q.Name == "www.example.com" || (q.Name == "old.example.com" && !oldGone.Load()) || (q.Name == "new.example.com" && oldGone.Load())
		switch {
		case q.Name == "example.com":
			return dnstest.Reply{}
		case live && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"192.0.2.10"}}
		case live:
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	wl := writeFile(t, "wl.txt", "www\nold\nnew\n")
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first.jsonl"), filepath.Join(dir, "second.jsonl")
	t1 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	t2 := t1.Add(48 * time.Hour)
	run := func(at time.Time, args ...string) {
		t.Helper()
		a := runArgs{args: append(localArgs(append([]string{"-dns-server", srv.Addr, "-type", "A", "-progress=false", "-w", wl, "-format", "jsonl"}, args...)...), "example.com"),
			now: func() time.Time { return at }}
		if code, out := runCLIWith(t, a); code != exitOK && code != exitChanges {
			t.Fatalf("exit %d\n%s", code, out)
		}
	}
	read := func(path string) map[string]output.Result {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return seenResults(t, string(b))
	}

	run(t1, "-o", first)
	for name, r := range read(first) {
		if r.FirstSeen != "2026-01-02T03:04:05Z" || r.LastSeen != r.FirstSeen {
			t.Errorf("first run: %s first %q last %q, want both the run's time", name, r.FirstSeen, r.LastSeen)
		}
	}

	oldGone.Store(true)
	run(t2, "-o", second, "-diff", first)
	got := read(second)
	if r := got["www.example.com"]; r.FirstSeen != "2026-01-02T03:04:05Z" || r.LastSeen != "2026-01-04T03:04:05Z" {
		t.Errorf("found again: first %q last %q, want the baseline's first and this run's last", r.FirstSeen, r.LastSeen)
	}
	if r := got["new.example.com"]; r.FirstSeen != "2026-01-04T03:04:05Z" || r.LastSeen != r.FirstSeen {
		t.Errorf("new name: first %q last %q, want this run's time", r.FirstSeen, r.LastSeen)
	}

	// stdout of the -diff run carries the removed name with its old dates.
	a := runArgs{args: append(localArgs("-dns-server", srv.Addr, "-type", "A", "-progress=false", "-w", wl, "-format", "jsonl", "-diff", first), "example.com"),
		now: func() time.Time { return t2 }}
	_, out := runCLIWith(t, a)
	if r := seenResults(t, out)["old.example.com"]; r.Change != "removed" || r.FirstSeen != "2026-01-02T03:04:05Z" || r.LastSeen != "2026-01-02T03:04:05Z" {
		t.Errorf("removed name: %+v, want the baseline's dates", r)
	}

	// subenum diff copies the dates from the file each name comes from.
	_, out = runCLIWith(t, runArgs{args: []string{"diff", "-format", "jsonl", first, second}})
	diffed := seenResults(t, out)
	if r := diffed["new.example.com"]; r.Change != "added" || r.FirstSeen != "2026-01-04T03:04:05Z" {
		t.Errorf("subenum diff added: %+v", r)
	}
	if r := diffed["old.example.com"]; r.Change != "missing" || r.LastSeen != "2026-01-02T03:04:05Z" {
		t.Errorf("subenum diff missing: %+v", r)
	}
}

// TestSimulatedResultsUndated covers #420: simulated and lab runs carry no
// first_seen or last_seen, so a seeded run's output is the same every time.
func TestSimulatedResultsUndated(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"-simulate", "-seed", "7", "-hit-rate", "100", "-w", writeFile(t, "wl.txt", "www\napi\n"), "-format", "csv", "example.com"},
		{"-simulate-zone", "lab1", "-format", "csv", "lab.example"},
	} {
		code, out := runCLI(t, "", args...)
		if code != exitOK || strings.Contains(out, "first_seen") || strings.Contains(out, "last_seen") {
			t.Errorf("%v: exit %d, output dated:\n%s", args, code, out)
		}
		header, _, _ := strings.Cut(out, "\n")
		if !slices.Contains(strings.Split(header, ","), "subdomain") {
			t.Errorf("%v: no CSV header: %q", args, header)
		}
	}
}
