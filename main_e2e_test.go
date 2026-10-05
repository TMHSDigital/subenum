package main

import (
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
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"help", []string{"-h"}, 0},
		{"unknown flag", []string{"-nope"}, 2},
		{"missing domain", []string{"-w", wl}, 1},
		{"two domains", []string{"-simulate", "-w", wl, "a.example", "b.example"}, 1},
		{"invalid flag value after domain", []string{"-simulate", "-w", wl, "example.com", "-t", "0"}, 1},
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
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
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
