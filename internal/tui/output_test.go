package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/TMHSDigital/subenum/internal/output"
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
	vals := formValues{
		domain: "example.com", dnsServer: "8.8.8.8:53", concurrency: 4, timeoutMs: 1000, attempts: 1,
		hitRate: 100, recordTypes: types, depth: 1, outputFile: path, format: format, formatName: formatName, simulate: true,
	}
	m := New(Options{Version: "test"})
	sized, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30}) // as a terminal sends first
	m = sized.(Model)
	next, _ := m.beginScan(vals, []string{"www", "api", "mail"}, 0)
	m = next.(Model)
	if m.state != stateScan {
		t.Fatalf("scan did not start: %s", m.form.err)
	}
	for m.events != nil {
		msg := listenForEvents(m.events)()
		next, _ := m.updateScan(msg)
		m = next.(Model)
		if _, done := msg.(doneMsg); done {
			break
		}
		if _, aborted := msg.(abortedMsg); aborted {
			t.Fatal("scan ended without a final event")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
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
	if got := m.inputs[inputForField[fieldDNSServer]].Value(); got != "tls://1.1.1.1" {
		t.Errorf("DNS server field = %q", got)
	}
}
