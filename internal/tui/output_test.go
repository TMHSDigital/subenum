package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// runTUIScan runs a simulated scan through the TUI model to completion and
// returns the output file's contents.
func runTUIScan(t *testing.T, format output.Format, formatName string, types []string) string {
	t.Helper()
	cfg := t.TempDir() // keep saveConfig away from the real user config dir
	t.Setenv("APPDATA", cfg)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("HOME", cfg)
	path := filepath.Join(t.TempDir(), "out."+formatName)
	runTUIModel(t, path, format, types)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// runTUIModel runs a simulated scan of www, api and mail through the TUI
// model to completion, writing the Output file path if it is not empty, and
// returns the model on the finished screen.
func runTUIModel(t *testing.T, path string, format output.Format, types []string) Model {
	t.Helper()
	vals := formValues{
		Options: scan.Options{Config: scan.Config{
			Domain: "example.com", DNSServer: "8.8.8.8:53", Concurrency: 4, Timeout: time.Second, Attempts: 1,
			HitRate: 100, Types: types, Depth: 1, Simulate: true,
		}},
		outputFile: path, format: format,
	}
	m := New(Options{Version: "test"})
	sized, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30}) // as a terminal sends first
	m = sized.(Model)
	next, _ := m.beginScan(wordlistLoadedMsg{cfg: vals, entries: []string{"www", "api", "mail"}})
	m = next.(Model)
	if m.state != stateScan {
		t.Fatalf("scan did not start: %s", m.form.err)
	}
	for m.events != nil {
		msg := listenForEvents(m.events)()
		next, _ := m.updateScan(msg)
		m = next.(Model)
		if ev := msg.(eventMsg); ev.Kind == scan.EventDone {
			if ev.Stopped {
				t.Fatal("scan ended without a final event")
			}
			break
		}
	}
	return m
}

// TestTUISavesResultsAfterTheScan covers #332: a scan run without an Output
// file can still be saved from the finished screen, in the format the path's
// extension names and limited to what the filter shows, and v shows each
// result's records. The prompt keeps the screen within the terminal.
func TestTUISavesResultsAfterTheScan(t *testing.T) {
	cfg := t.TempDir() // keep saveConfig away from the real user config dir
	t.Setenv("APPDATA", cfg)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("HOME", cfg)
	m := runTUIModel(t, "", output.FormatText, []string{"A"})
	if !m.scanView.done {
		t.Fatal("scan did not finish")
	}
	press := func(keys ...tea.KeyPressMsg) {
		t.Helper()
		for _, k := range keys {
			next, _ := m.updateScan(k)
			m = next.(Model)
		}
	}
	typeIn := func(s string) {
		t.Helper()
		for _, r := range s {
			press(typeText(string(r)))
		}
	}
	clearPath := func() {
		t.Helper()
		for range []rune(m.scanView.savePath) {
			press(keyBackspace)
		}
	}
	dir := t.TempDir()

	// Records: v toggles them under each result.
	press(typeText("v"))
	if view := m.scanView.viewport.View(); !strings.Contains(view, "A=") {
		t.Errorf("v did not show the records:\n%s", view)
	}

	// Save everything as CSV; the prompt starts from the form's format.
	press(typeText("s"))
	if !m.scanView.saving || m.scanView.savePath != "subenum-example.com.txt" {
		t.Fatalf("s: saving %v, path %q", m.scanView.saving, m.scanView.savePath)
	}
	if got := lipgloss.Height(m.content()); got != 30 {
		t.Errorf("view with the save prompt is %d lines, want 30", got)
	}
	clearPath()
	all := filepath.Join(dir, "all.csv")
	typeIn(all) // q and r in the path must not quit or start a new scan
	press(keyEnter)
	if m.state != stateScan || m.scanView.saving {
		t.Fatalf("after enter: state %v, saving %v", m.state, m.scanView.saving)
	}
	data, err := os.ReadFile(all)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) != 4 || !strings.HasPrefix(lines[0], "subdomain,") {
		t.Errorf("CSV is not a header and 3 rows:\n%s", data)
	}
	if !strings.Contains(m.content(), "Saved 3 results to") {
		t.Errorf("no saved notice:\n%s", m.content())
	}

	// Save what a filter shows, as JSONL, which ends with the summary.
	press(typeText("/"))
	typeIn("www")
	press(keyEnter, typeText("s"))
	clearPath()
	some := filepath.Join(dir, "www.jsonl")
	typeIn(some)
	press(keyEnter)
	data, err = os.ReadFile(some)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var s output.Summary
	if len(lines) != 2 || !strings.Contains(lines[0], `"www.example.com"`) || json.Unmarshal([]byte(lines[1]), &s) != nil || s.Type != "summary" {
		t.Errorf("filtered JSONL is not www and the summary:\n%s", data)
	}
	if !strings.Contains(m.content(), "the 1 of 3 the filter shows") {
		t.Errorf("no filtered notice:\n%s", m.content())
	}

	// esc closes the prompt without saving; a path that cannot be created
	// is reported and leaves the exit code alone.
	press(typeText("s"), keyEsc)
	if m.scanView.saving {
		t.Error("esc did not close the prompt")
	}
	press(typeText("s"))
	clearPath()
	typeIn(filepath.Join(dir, "missing", "x.txt"))
	press(keyEnter)
	if !strings.Contains(m.content(), "cannot save results") || exitCode(m) != 0 {
		t.Errorf("failed save: exit %d, view:\n%s", exitCode(m), m.content())
	}
}

// TestTUIOutputMatchesCLI covers #118: a TUI CSV has the takeover column
// when CNAME records are requested, and a TUI JSONL file ends with the
// run-quality summary, as the CLI's files do.
func TestTUIOutputMatchesCLI(t *testing.T) {
	csv := runTUIScan(t, output.FormatCSV, "csv", []string{"A", "CNAME"})
	if header, _, _ := strings.Cut(csv, "\n"); !strings.Contains(header, "takeover_candidate") {
		t.Errorf("CSV header %q lacks takeover_candidate", header)
	}

	jsonl := strings.TrimSpace(runTUIScan(t, output.FormatJSONL, "jsonl", []string{"A"}))
	lines := strings.Split(jsonl, "\n")
	var s output.Summary
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &s); err != nil || s.Type != "summary" {
		t.Fatalf("last JSONL line is not the summary (err %v):\n%s", err, jsonl)
	}
	if len(s.Targets) != 1 || s.Targets[0].Domain != "example.com" || s.Verdict == "" || !s.Simulated || s.Version != "test" {
		t.Errorf("summary = %+v", s)
	}
	if len(lines) != 4 {
		t.Errorf("got %d JSONL lines, want 3 results and the summary", len(lines))
	}
}

// TestSettingsPrefillTheForm covers #118: values from SUBENUM_* or the
// config file override the remembered form values.
func TestSettingsPrefillTheForm(t *testing.T) {
	sc := withSettings(savedConfig{DNSServer: "8.8.8.8:53", Concurrency: 100, Simulate: false}, map[string]string{
		"dns-server": "tls://1.1.1.1", "t": "20", "simulate": "true", "type": "A,CNAME", "unrelated": "x",
	})
	if sc.DNSServer != "tls://1.1.1.1" || sc.Concurrency != 20 || !sc.Simulate || sc.Types != "A,CNAME" {
		t.Errorf("withSettings = %+v", sc)
	}
	m := newFormModel(sc)
	if got := m.inputs[fieldDNSServer].Value(); got != "tls://1.1.1.1" {
		t.Errorf("DNS server field = %q", got)
	}
}
