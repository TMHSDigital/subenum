package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// decodeLogLines parses every line of stderr as one JSON object.
func decodeLogLines(t *testing.T, stderr string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(stderr, "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stderr line is not JSON: %v\n%q", err, line)
		}
		for _, k := range []string{"time", "level", "kind", "message"} {
			if _, ok := m[k]; !ok {
				t.Errorf("line %q has no %q field", line, k)
			}
		}
		out = append(out, m)
	}
	return out
}

func TestParseLogFormat(t *testing.T) {
	for in, want := range map[string]LogFormat{"": LogText, "text": LogText, "JSON": LogJSON, " json ": LogJSON, "jsonl": LogJSON} {
		if got, err := ParseLogFormat(in); err != nil || got != want {
			t.Errorf("ParseLogFormat(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseLogFormat("yaml"); err == nil {
		t.Error("ParseLogFormat(yaml) succeeded")
	}
}

// TestLogJSONLines covers #198: every diagnostic is one JSON line, a text
// marker becomes the level, engine notices carry their setting codes, and
// blank spacer lines are dropped.
func TestLogJSONLines(t *testing.T) {
	var stderr bytes.Buffer
	w := New(nil, false, FormatText)
	w.SetStderr(&stderr)
	w.SetLogFormat(LogJSON)
	w.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 6e6, time.UTC) }

	w.Info("Note: a note")
	w.Info("")
	w.Info("Warning: careful")
	w.SetTarget("example.com")
	w.Notice("loud")
	w.Error("bad %d", 1)
	w.Verbose("Resolved: www.example.com")
	w.ScanNotice("cap", "query cap reached ({max_queries} 2); skipped {max_queries} {bogus}")
	if got := w.ScanError("{depth} too deep"); got != "-depth too deep" {
		t.Errorf("ScanError returned %q", got)
	}
	w.SetTarget("")
	w.Info("  indented row  ")

	want := []string{
		`{"time":"2026-01-02T03:04:05.006Z","level":"info","kind":"message","message":"a note"}`,
		`{"time":"2026-01-02T03:04:05.006Z","level":"warn","kind":"message","message":"careful"}`,
		`{"time":"2026-01-02T03:04:05.006Z","level":"notice","kind":"message","target":"example.com","message":"loud"}`,
		`{"time":"2026-01-02T03:04:05.006Z","level":"error","kind":"message","target":"example.com","message":"bad 1"}`,
		`{"time":"2026-01-02T03:04:05.006Z","level":"debug","kind":"verbose","target":"example.com","message":"Resolved: www.example.com"}`,
		`{"time":"2026-01-02T03:04:05.006Z","level":"warn","kind":"cap","target":"example.com","message":"query cap reached (-max-queries 2); skipped -max-queries {bogus}","settings":["max_queries"]}`,
		`{"time":"2026-01-02T03:04:05.006Z","level":"error","kind":"scan","target":"example.com","message":"-depth too deep","settings":["depth"]}`,
		`{"time":"2026-01-02T03:04:05.006Z","level":"info","kind":"message","message":"indented row"}`,
	}
	got := strings.Split(strings.TrimSuffix(stderr.String(), "\n"), "\n")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("stderr:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	decodeLogLines(t, stderr.String())
}

// TestLogJSONProgress: under -log-format json a progress tick is a JSON event
// with its numbers, never a carriage-return redraw.
func TestLogJSONProgress(t *testing.T) {
	var stderr bytes.Buffer
	w := New(nil, false, FormatText)
	w.SetStderr(&stderr)
	w.SetLogFormat(LogJSON)
	start := time.Unix(0, 0)
	now := start
	w.eta.Now = func() time.Time { return now }
	for i := int64(1); i <= 5; i++ {
		now = start.Add(time.Duration(i) * 2 * time.Second)
		w.Progress(float64(i*10), i*10, 100, i)
	}
	w.ProgressDone()
	if strings.Contains(stderr.String(), "\r") {
		t.Errorf("JSON progress has a carriage return: %q", stderr.String())
	}
	lines := decodeLogLines(t, stderr.String())
	if len(lines) != 5 {
		t.Fatalf("got %d lines, want 5:\n%s", len(lines), stderr.String())
	}
	last := lines[4]
	if last["kind"] != "progress" || last["level"] != "info" {
		t.Errorf("progress line = %v", last)
	}
	p, _ := last["progress"].(map[string]any)
	if p["percent"] != 50.0 || p["processed"] != 50.0 || p["total"] != 100.0 || p["found"] != 5.0 {
		t.Errorf("progress payload = %v", p)
	}
	if _, ok := p["eta_seconds"]; !ok {
		t.Errorf("progress payload has no eta_seconds once the estimate warms up: %v", p)
	}
}

// TestLogTextUnchanged: the default text format prints exactly what it did
// before #198, engine tokens rendered as flags.
func TestLogTextUnchanged(t *testing.T) {
	var stderr bytes.Buffer
	w := New(nil, false, FormatText)
	w.SetStderr(&stderr)
	w.SetTarget("example.com")
	w.Info("Note: a note")
	w.Info("")
	w.Error("bad %d", 1)
	w.Verbose("Resolved: x")
	w.ScanNotice("cap", "Warning: cap ({max_queries} 2)")
	w.ScanError("{depth} too deep")
	want := "Note: a note\n\nError: bad 1\nResolved: x\nWarning: cap (-max-queries 2)\nError: -depth too deep\n"
	if stderr.String() != want {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}
}

// TestLogQuiet: -silent keeps Info, Verbose, ScanNotice and Progress quiet in
// either format; Notice and Error still print.
func TestLogQuiet(t *testing.T) {
	for _, f := range []LogFormat{LogText, LogJSON} {
		var stderr bytes.Buffer
		w := New(nil, false, FormatText)
		w.SetStderr(&stderr)
		w.SetLogFormat(f)
		w.SetQuiet(true)
		w.Info("info")
		w.Verbose("verbose")
		w.ScanNotice("cap", "cap")
		w.Progress(50, 1, 2, 0)
		w.Notice("notice")
		w.Error("error")
		got := stderr.String()
		if strings.Contains(got, "info") || strings.Contains(got, "verbose") || strings.Contains(got, "cap") || strings.Contains(got, "Progress") {
			t.Errorf("format %d: quiet output leaked: %q", f, got)
		}
		if !strings.Contains(got, "notice") || !strings.Contains(got, "error") {
			t.Errorf("format %d: Notice or Error missing: %q", f, got)
		}
	}
}
