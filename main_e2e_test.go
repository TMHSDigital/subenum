package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// runCLI invokes run() as the binary would, with args after the program name,
// optional stdin, and stdout captured. Stderr is discarded. Simulation mode
// keeps these tests free of network I/O.
func runCLI(t *testing.T, stdin string, args ...string) (int, string) {
	t.Helper()
	oldArgs, oldStdout, oldStderr, oldStdin := os.Args, os.Stdout, os.Stderr, os.Stdin
	t.Cleanup(func() { os.Args, os.Stdout, os.Stderr, os.Stdin = oldArgs, oldStdout, oldStderr, oldStdin })

	os.Args = append([]string{ProgramName}, args...)
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devnull.Close() }()
	os.Stderr = devnull

	if stdin != "" {
		in, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			_, _ = io.WriteString(w, stdin)
			_ = w.Close()
		}()
		os.Stdin = in
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	outCh := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		outCh <- string(b)
	}()
	code := run()
	_ = w.Close()
	return code, <-outCh
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const e2eWords = "www\nmail\napi\ndev\nshop\nblog\n"

func TestE2ESimulateJSON(t *testing.T) {
	wl := writeFile(t, "wl.txt", e2eWords)
	code, out := runCLI(t, "", "-simulate", "-hit-rate", "100", "-progress=false", "-format", "json", "-w", wl, "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var res []struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
	}
	if len(res) != 6 {
		t.Errorf("got %d results, want 6", len(res))
	}
}

func TestE2EDomainListSingleJSONArray(t *testing.T) {
	wl := writeFile(t, "wl.txt", e2eWords)
	dl := writeFile(t, "domains.txt", "# targets\na.example\nb.example\n")
	code, out := runCLI(t, "", "-simulate", "-hit-rate", "100", "-progress=false", "-format", "json", "-w", wl, "-dL", dl)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var res []struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("-dL output is not a single JSON array: %v", err)
	}
	apexes := map[string]int{}
	for _, r := range res {
		apexes[r.Subdomain[strings.Index(r.Subdomain, ".")+1:]]++
	}
	if apexes["a.example"] != 6 || apexes["b.example"] != 6 {
		t.Errorf("results per apex = %v, want 6 each", apexes)
	}
}

func TestE2EStdinWordlistPlainOutput(t *testing.T) {
	code, out := runCLI(t, "WWW\nmail\n# comment\n", "-simulate", "-hit-rate", "100", "-progress=false", "-w", "-", "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Fields(out)
	sort.Strings(lines)
	if strings.Join(lines, ",") != "mail.example.com,www.example.com" {
		t.Errorf("piped stdout = %q, want bare names", out)
	}
}

func TestE2ESeedReproducible(t *testing.T) {
	wl := writeFile(t, "wl.txt", e2eWords+"vpn\ncdn\nadmin\nportal\n")
	args := []string{"-simulate", "-seed", "99", "-hit-rate", "50", "-t", "1", "-progress=false", "-show-records", "-w", wl, "example.com"}
	_, first := runCLI(t, "", args...)
	_, second := runCLI(t, "", args...)
	if first == "" || first != second {
		t.Errorf("same -seed gave different output:\n%s\n---\n%s", first, second)
	}
}

func TestE2EExitCodes(t *testing.T) {
	wl := writeFile(t, "wl.txt", e2eWords)
	empty := writeFile(t, "empty.txt", "# only comments\n")
	// The second domain is so long that no wordlist entry fits under it, so
	// that target fails while the first completes.
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 54) + ".com"
	partial := writeFile(t, "partial.txt", "example.com\n"+long+"\n")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"help", []string{"-h"}, 0},
		{"unknown flag", []string{"-nope"}, 2},
		{"missing domain", []string{"-w", wl}, 2},
		{"two domains", []string{"-simulate", "-w", wl, "a.example", "b.example"}, 2},
		{"invalid flag value after domain", []string{"-simulate", "-w", wl, "example.com", "-t", "0"}, 2},
		{"invalid format", []string{"-simulate", "-format", "xml", "-w", wl, "example.com"}, 2},
		{"-dL partial failure", []string{"-simulate", "-progress=false", "-w", wl, "-dL", partial}, 3},
		{"wordlist without valid entries", []string{"-simulate", "-w", empty, "example.com"}, 1},
		{"domain list without valid domains", []string{"-simulate", "-w", wl, "-dL", empty}, 1},
		{"unwritable output file", []string{"-simulate", "-progress=false", "-w", wl, "-o", t.TempDir(), "example.com"}, 1},
		{"ok", []string{"-simulate", "-progress=false", "-w", wl, "example.com"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := runCLI(t, "", tc.args...); code != tc.want {
				t.Errorf("exit %d, want %d", code, tc.want)
			}
		})
	}
}

// TestE2EFailedRunKeepsOutputFile covers #52: a run that fails preflight
// leaves an existing -o file byte-for-byte unchanged, while a run that
// finishes replaces it.
func TestE2EFailedRunKeepsOutputFile(t *testing.T) {
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()

	wl := writeFile(t, "wl.txt", e2eWords)
	const prev = "PREVIOUS RESULTS\n"
	outPath := writeFile(t, "prev.txt", prev)

	code, _ := runCLI(t, "", "-dns-server", pc.LocalAddr().String(), "-timeout", "100", "-progress=false",
		"-format", "json", "-w", wl, "-o", outPath, "example.invalid")
	if code != 1 {
		t.Fatalf("exit %d, want 1 (preflight failure)", code)
	}
	if got, _ := os.ReadFile(outPath); string(got) != prev {
		t.Fatalf("output file changed by a failed run: %q", got)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(outPath), ".*.tmp")); len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}

	code, _ = runCLI(t, "", "-simulate", "-hit-rate", "100", "-progress=false", "-w", wl, "-o", outPath, "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got, _ := os.ReadFile(outPath); !strings.Contains(string(got), "www.example.com") {
		t.Fatalf("finished run did not replace the output file: %q", got)
	}
}

// runCLIMerged is runCLI with stdout and stderr sharing one pipe, like
// `subenum ... 2>&1 | tee log`.
func runCLIMerged(t *testing.T, args ...string) (int, string) {
	t.Helper()
	oldArgs, oldStdout, oldStderr := os.Args, os.Stdout, os.Stderr
	t.Cleanup(func() { os.Args, os.Stdout, os.Stderr = oldArgs, oldStdout, oldStderr })
	os.Args = append([]string{ProgramName}, args...)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = w, w
	outCh := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		outCh <- string(b)
	}()
	code := run()
	_ = w.Close()
	return code, <-outCh
}

// TestE2EMergedStreamsHaveNoCarriageReturns covers #78: with stdout and
// stderr merged into a non-terminal, results are never glued onto a progress
// line. Progress is off by default there and whole lines when requested.
func TestE2EMergedStreamsHaveNoCarriageReturns(t *testing.T) {
	var words strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&words, "w%d\n", i)
	}
	wl := writeFile(t, "wl.txt", words.String())
	base := []string{"-simulate", "-seed", "1", "-hit-rate", "50", "-rate", "15", "-w", wl, "example.com"}

	for _, tc := range []struct {
		name         string
		extra        []string
		wantProgress bool
	}{
		{"default", nil, false},
		{"explicit -progress", []string{"-progress"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := runCLIMerged(t, append(tc.extra, base...)...)
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			if strings.Contains(out, "\r") {
				t.Fatalf("carriage return in merged output:\n%q", out)
			}
			results := 0
			for _, line := range strings.Split(out, "\n") {
				if strings.HasSuffix(line, ".example.com") {
					results++
					if strings.ContainsAny(line, " :") {
						t.Fatalf("result line is not a bare hostname: %q", line)
					}
				}
			}
			if results == 0 {
				t.Fatalf("no results in merged output:\n%s", out)
			}
			if got := strings.Contains(out, "Progress:"); got != tc.wantProgress {
				t.Fatalf("progress lines present = %v, want %v\n%s", got, tc.wantProgress, out)
			}
		})
	}
}

// TestE2EDomainFormsGiveIdenticalOutput covers #54: the same target written
// as Example.COM., example.com, a URL, or via -dL scans identically.
func TestE2EDomainFormsGiveIdenticalOutput(t *testing.T) {
	wl := writeFile(t, "wl.txt", e2eWords)
	common := []string{"-simulate", "-seed", "7", "-hit-rate", "100", "-progress=false", "-w", wl}
	scan := func(args ...string) string {
		code, out := runCLI(t, "", append(append([]string{}, common...), args...)...)
		if code != 0 {
			t.Fatalf("%v: exit %d", args, code)
		}
		lines := strings.Fields(out)
		sort.Strings(lines)
		return strings.Join(lines, "\n")
	}
	want := scan("example.com")
	if !strings.Contains(want, "www.example.com") {
		t.Fatalf("baseline output missing www.example.com:\n%s", want)
	}
	dl := writeFile(t, "domains.txt", "Example.COM.\n")
	for _, args := range [][]string{{"Example.COM."}, {"https://example.com/"}, {"-dL", dl}} {
		if got := scan(args...); got != want {
			t.Errorf("%v output differs:\n%s\nwant:\n%s", args, got, want)
		}
	}
}

// TestE2ECLIPolish covers #58: missing arguments are named before the usage
// text, and -version prints before any simulation banner.
func TestE2ECLIPolish(t *testing.T) {
	// Without -w the bundled list is used, and the user is told so (#63).
	// Simulated, so no DNS traffic leaves the test.
	code, out := runCLIMerged(t, "-simulate", "-hit-rate", "1", "-seed", "1", "example.com")
	if code != 0 || !strings.Contains(out, "No -w given: using the bundled top-5000 list") {
		t.Errorf("no -w: exit %d, output lacks the bundled-list notice:\n%.400s", code, out)
	}
	wl := writeFile(t, "wl.txt", e2eWords)
	_, out = runCLIMerged(t, "-w", wl)
	if !strings.Contains(out, "Error: missing <domain>") {
		t.Errorf("missing domain not named:\n%s", out)
	}
	code, out = runCLIMerged(t, "-simulate", "-version")
	if code != 0 || !strings.HasPrefix(out, ProgramName) || strings.Contains(out, "SIMULATION MODE ACTIVE") {
		t.Errorf("-simulate -version: exit %d, output:\n%s", code, out)
	}
}

// TestE2EHelpListsExitCodes covers #82: -h documents the exit codes.
func TestE2EHelpListsExitCodes(t *testing.T) {
	code, out := runCLIMerged(t, "-h")
	if code != 0 || !strings.Contains(out, "Exit codes:") || !strings.Contains(out, "143") {
		t.Errorf("-h: exit %d, output missing the exit-code table:\n%s", code, out)
	}
}

// TestE2ESummary covers #70: jsonl output ends with a schema-versioned
// summary, and -stats records a verdict even when the scan fails.
func TestE2ESummary(t *testing.T) {
	wl := writeFile(t, "wl.txt", e2eWords)
	code, out := runCLI(t, "", "-simulate", "-hit-rate", "100", "-progress=false", "-format", "jsonl", "-w", wl, "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var sum struct {
		Type    string `json:"type"`
		Schema  int    `json:"schema"`
		Verdict string `json:"verdict"`
		Targets []struct {
			Domain   string `json:"domain"`
			Status   string `json:"status"`
			Outcomes struct {
				Resolved int `json:"resolved"`
			} `json:"outcomes"`
		} `json:"targets"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &sum); err != nil {
		t.Fatalf("last jsonl line is not JSON: %v", err)
	}
	if sum.Type != "summary" || sum.Schema != 1 || sum.Verdict != "complete" ||
		len(sum.Targets) != 1 || sum.Targets[0].Status != "ok" || sum.Targets[0].Outcomes.Resolved != 6 {
		t.Fatalf("summary = %+v\nfrom %s", sum, lines[len(lines)-1])
	}
	if len(lines) != 7 {
		t.Errorf("got %d lines, want 6 results + 1 summary", len(lines))
	}

	// A preflight failure still writes -stats, with an unreliable verdict.
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	stats := filepath.Join(t.TempDir(), "run.json")
	code, _ = runCLI(t, "", "-dns-server", pc.LocalAddr().String(), "-timeout", "100", "-progress=false",
		"-stats", stats, "-w", wl, "example.invalid")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	data, err := os.ReadFile(stats)
	if err != nil {
		t.Fatalf("-stats file not written: %v", err)
	}
	sum.Targets = nil
	if err := json.Unmarshal(data, &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Verdict != "unreliable" || len(sum.Targets) != 1 || sum.Targets[0].Status != "failed" {
		t.Fatalf("failed-run summary = %s", data)
	}
}

// TestE2EExclude covers #87: a recursive simulated scan with -exclude never
// reports names in the excluded branch, and the summary counts them.
func TestE2EExclude(t *testing.T) {
	wl := writeFile(t, "wl.txt", "dev\nwww\napi\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	code, out := runCLI(t, "", "-simulate", "-hit-rate", "100", "-progress=false", "-recursive", "-depth", "2",
		"-exclude", "*.dev.example.com", "-stats", stats, "-w", wl, "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, line := range strings.Fields(out) {
		if strings.HasSuffix(line, ".dev.example.com") {
			t.Fatalf("excluded name in results: %s", line)
		}
	}
	if !strings.Contains(out, "dev.example.com") || !strings.Contains(out, "dev.www.example.com") {
		t.Fatalf("in-scope names missing:\n%s", out)
	}
	data, err := os.ReadFile(stats)
	if err != nil {
		t.Fatal(err)
	}
	var sum struct {
		Targets []struct {
			Outcomes struct {
				Excluded int `json:"excluded"`
			} `json:"outcomes"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &sum); err != nil || len(sum.Targets) != 1 || sum.Targets[0].Outcomes.Excluded != 3 {
		t.Fatalf("summary excluded count wrong (err %v): %s", err, data)
	}

	if code, _ := runCLI(t, "", "-simulate", "-exclude", "not a domain", "-w", wl, "example.com"); code != 2 {
		t.Errorf("invalid -exclude pattern: exit %d, want 2", code)
	}
}

// startNXServer is a minimal UDP DNS server that answers NXDOMAIN to every
// query, enough to drive live-mode CLI runs hermetically.
func startNXServer(t *testing.T) string {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			resp := append([]byte(nil), buf[:n]...)
			resp[2] |= 0x80                   // QR: response
			resp[3] = (resp[3] & 0xF0) | 0x03 // RCODE: NXDOMAIN
			_, _ = pc.WriteTo(resp, src)
		}
	}()
	return pc.LocalAddr().String()
}

// TestE2EResolverPool covers #69: -r spreads lookups over the listed
// resolvers and the summary reports each one's accounting.
func TestE2EResolverPool(t *testing.T) {
	trusted, r1, r2 := startNXServer(t), startNXServer(t), startNXServer(t)
	wl := writeFile(t, "wl.txt", e2eWords)
	list := writeFile(t, "resolvers.txt", "# pool\n"+r1+"\n"+r2+"\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	code, _ := runCLI(t, "", "-dns-server", trusted, "-r", list, "-type", "A", "-progress=false",
		"-stats", stats, "-w", wl, "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(stats)
	if err != nil {
		t.Fatal(err)
	}
	var sum struct {
		Resolver  string `json:"resolver"`
		Resolvers []struct {
			Address string `json:"address"`
			Lookups int    `json:"lookups"`
		} `json:"resolvers"`
	}
	if err := json.Unmarshal(data, &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Resolver != trusted || len(sum.Resolvers) != 2 {
		t.Fatalf("summary resolvers wrong: %s", data)
	}
	total := 0
	for _, r := range sum.Resolvers {
		if r.Lookups == 0 {
			t.Errorf("resolver %s got no lookups: %s", r.Address, data)
		}
		total += r.Lookups
	}
	if total != 6 {
		t.Errorf("pool lookups = %d, want 6 (one per wordlist entry)", total)
	}

	bad := writeFile(t, "bad.txt", "dns.example.com\n")
	if code, _ := runCLI(t, "", "-r", bad, "-w", wl, "example.com"); code != 2 {
		t.Errorf("invalid resolver list: exit %d, want 2", code)
	}
}

// TestE2EDiff covers #84: -diff reports only added and removed names, exits
// 4 on changes, keeps the full results in -o, and suppresses "removed" when
// the run was not complete.
func TestE2EDiff(t *testing.T) {
	dir := t.TempDir()
	prev := filepath.Join(dir, "prev.jsonl")
	sim := []string{"-simulate", "-seed", "1", "-hit-rate", "100", "-progress=false"}
	run := func(words string, extra ...string) (int, string) {
		wl := writeFile(t, "wl.txt", words)
		return runCLI(t, "", append(append(append([]string{}, sim...), extra...), "-w", wl, "example.com")...)
	}
	if code, _ := run("www\nmail\napi\n", "-format", "jsonl", "-o", prev); code != 0 {
		t.Fatalf("baseline exit %d", code)
	}

	cur := filepath.Join(dir, "cur.jsonl")
	code, out := run("www\nmail\ndev\n", "-format", "jsonl", "-diff", prev, "-o", cur)
	if code != 4 {
		t.Fatalf("exit %d, want 4 (changes)", code)
	}
	changes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var r struct {
			Type      string `json:"type"`
			Subdomain string `json:"subdomain"`
			Change    string `json:"change"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad jsonl line %q: %v", line, err)
		}
		if r.Type != "summary" {
			changes[r.Subdomain] = r.Change
		}
	}
	if len(changes) != 2 || changes["dev.example.com"] != "added" || changes["api.example.com"] != "removed" {
		t.Fatalf("changes = %v, want dev added and api removed only", changes)
	}
	full, err := os.ReadFile(cur)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"www.example.com", "mail.example.com", "dev.example.com"} {
		if !strings.Contains(string(full), `"subdomain":"`+name+`"`) {
			t.Errorf("-o is missing %s; it should hold the full results:\n%s", name, full)
		}
	}
	if strings.Contains(string(full), `"change"`) {
		t.Errorf("-o should hold plain results, not changes:\n%s", full)
	}

	// Text format, no changes against the file just written: exit 0, no output.
	if code, out := run("www\nmail\ndev\n", "-diff", cur); code != 0 || strings.TrimSpace(out) != "" {
		t.Fatalf("unchanged run: exit %d, output %q", code, out)
	}
	// Text prefixes.
	if _, out := run("www\nmail\ndev\nvpn\n", "-diff", cur); !strings.Contains(out, "+ vpn.example.com") {
		t.Fatalf("text diff = %q, want '+ vpn.example.com'", out)
	}
	// A capped (degraded) run must not claim names were removed.
	if _, out := run("www\nmail\ndev\n", "-diff", cur, "-max-queries", "1"); strings.Contains(out, "- ") {
		t.Fatalf("degraded run reported removals: %q", out)
	}
}
