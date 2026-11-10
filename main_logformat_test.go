package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// runCLIStreams runs the CLI with stdout and stderr captured apart.
func runCLIStreams(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runWith(runArgs{args: args, stdin: strings.NewReader(""), stdout: &out, stderr: &errOut})
	return code, out.String(), errOut.String()
}

// logLine is one -log-format json line.
type logLine struct {
	Time     string   `json:"time"`
	Level    string   `json:"level"`
	Kind     string   `json:"kind"`
	Target   string   `json:"target"`
	Message  string   `json:"message"`
	Settings []string `json:"settings"`
}

// parseLogLines fails the test unless every stderr line is a JSON object
// with time, level, kind and message (#198).
func parseLogLines(t *testing.T, stderr string) []logLine {
	t.Helper()
	if stderr == "" {
		return nil
	}
	var lines []logLine
	for _, raw := range strings.Split(strings.TrimSuffix(stderr, "\n"), "\n") {
		var l logLine
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Fatalf("stderr line is not a JSON object of the schema: %v\n%q", err, raw)
		}
		if l.Time == "" || l.Level == "" || l.Kind == "" || l.Message == "" {
			t.Errorf("stderr line misses a required field: %q", raw)
		}
		switch l.Level {
		case "error", "warn", "notice", "info", "debug":
		default:
			t.Errorf("unknown level %q in %q", l.Level, raw)
		}
		lines = append(lines, l)
	}
	return lines
}

// TestE2ELogFormatJSON covers #198: under -log-format json every stderr line
// is a JSON object, engine notices carry their setting codes and the target,
// and stdout is byte for byte what the text format prints.
func TestE2ELogFormatJSON(t *testing.T) {
	wl := writeFile(t, "wl.txt", e2eWords)
	// One worker keeps the result order fixed between the two runs.
	base := []string{"-simulate", "-seed", "1", "-hit-rate", "100", "-t", "1", "-v", "-max-queries", "3", "-format", "jsonl", "-w", wl, "example.com"}
	_, textOut, textErr := runCLIStreams(t, base...)
	code, jsonOut, jsonErr := runCLIStreams(t, append([]string{"-log-format", "json"}, base...)...)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, jsonErr)
	}
	// The trailing summary record carries the start time; compare the rest.
	withoutSummary := func(s string) string {
		var keep []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.Contains(l, `"type":"summary"`) {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	if strings.Count(jsonOut, `"type":"summary"`) != 1 || strings.Count(textOut, `"type":"summary"`) != 1 {
		t.Errorf("want one summary record in each stdout:\n%s\n%s", jsonOut, textOut)
	}
	if jsonOut, textOut := withoutSummary(jsonOut), withoutSummary(textOut); jsonOut != textOut {
		t.Errorf("stdout differs under -log-format json:\n%s\nwant:\n%s", jsonOut, textOut)
	}
	if strings.HasPrefix(textErr, "{") {
		t.Errorf("text stderr starts like JSON: %q", textErr)
	}
	lines := parseLogLines(t, jsonErr)
	var sawSim, sawVerbose, sawCap bool
	for _, l := range lines {
		switch {
		case l.Kind == "simulation" && l.Level == "notice":
			sawSim = true
		case l.Kind == "verbose" && l.Level == "debug":
			sawVerbose = true
			if l.Target != "example.com" {
				t.Errorf("verbose line target = %q, want example.com", l.Target)
			}
		case l.Kind == "cap":
			sawCap = true
			if len(l.Settings) != 1 || l.Settings[0] != "max_queries" || !strings.Contains(l.Message, "-max-queries") {
				t.Errorf("cap notice = %+v, want settings [max_queries] and the flag in the message", l)
			}
			if l.Target != "example.com" {
				t.Errorf("cap notice target = %q", l.Target)
			}
		}
		if strings.HasPrefix(l.Message, "Warning: ") || strings.HasPrefix(l.Message, "Error: ") {
			t.Errorf("level marker left in message: %q", l.Message)
		}
	}
	if !sawSim || !sawVerbose || !sawCap {
		t.Errorf("simulation notice %v, verbose line %v, cap notice %v; want all\n%s", sawSim, sawVerbose, sawCap, jsonErr)
	}
}

// TestE2ELogFormatJSONErrors: usage errors, including those the flag package
// reports and a missing domain, are JSON lines too, without the usage text.
func TestE2ELogFormatJSONErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown flag":   {"-log-format", "json", "-bogus", "example.com"},
		"missing domain": {"-log-format", "json", "-simulate"},
		"bad format":     {"-log-format", "json", "-format", "yaml", "-simulate", "example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runCLIStreams(t, args...)
			if code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
			if stdout != "" {
				t.Errorf("stdout = %q", stdout)
			}
			lines := parseLogLines(t, stderr)
			if len(lines) != 1 || lines[0].Level != "error" {
				t.Errorf("stderr = %q, want one error line", stderr)
			}
		})
	}
	code, _, stderr := runCLIStreams(t, "-log-format", "yaml", "-simulate", "example.com")
	if code != 2 || !strings.Contains(stderr, "invalid -log-format") {
		t.Errorf("-log-format yaml: exit %d, stderr %q", code, stderr)
	}
}

// TestE2ELogFormatJSONSilentAndEnv: -silent keeps its meaning (only the
// simulation notice), and SUBENUM_LOG_FORMAT selects the format like any
// other flag.
func TestE2ELogFormatJSONSilentAndEnv(t *testing.T) {
	t.Setenv("SUBENUM_LOG_FORMAT", "json")
	wl := writeFile(t, "wl.txt", e2eWords)
	code, stdout, stderr := runCLIStreams(t, "-silent", "-simulate", "-seed", "1", "-hit-rate", "100", "-w", wl, "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if n := len(strings.Split(strings.TrimSpace(stdout), "\n")); n != 6 {
		t.Errorf("stdout has %d names, want 6", n)
	}
	lines := parseLogLines(t, stderr)
	if len(lines) != 1 || lines[0].Kind != "simulation" {
		t.Errorf("stderr under -silent = %q, want only the simulation notice", stderr)
	}
}

// TestE2ELogFormatJSONProgress: explicit -progress under json gives progress
// events, never carriage-return redraws; without it there are none.
func TestE2ELogFormatJSONProgress(t *testing.T) {
	wl := writeFile(t, "wl.txt", e2eWords)
	args := []string{"-log-format", "json", "-simulate", "-seed", "1", "-w", wl, "example.com"}
	_, _, stderr := runCLIStreams(t, args...)
	for _, l := range parseLogLines(t, stderr) {
		if l.Kind == "progress" {
			t.Errorf("progress event without -progress: %+v", l)
		}
	}
	_, _, stderr = runCLIStreams(t, append([]string{"-progress"}, args...)...)
	if strings.Contains(stderr, "\r") {
		t.Errorf("carriage return under -log-format json: %q", stderr)
	}
	parseLogLines(t, stderr)
}
