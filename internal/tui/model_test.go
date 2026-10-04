package tui

import (
	"bufio"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
)

// TestFinalizeOutputGatesStructuredOutput locks in the TUI's replication of the
// CLI contract: structured output is finalized only on the success path
// (doneMsg -> finalizeOutput(true)). The early-error path
// (abortedMsg -> finalizeOutput(false)) must close the file without emitting an
// empty JSON array, the bug fixed once for the CLI in main.run.
func TestFinalizeOutputGatesStructuredOutput(t *testing.T) {
	mkModel := func(t *testing.T) (*Model, string) {
		t.Helper()
		f, err := os.CreateTemp("", "tui-out-*.json")
		if err != nil {
			t.Fatal(err)
		}
		buf := bufio.NewWriter(f)
		m := &Model{
			out:     output.NewFile(buf, false, output.FormatJSON),
			outBuf:  buf,
			outFile: f,
		}
		return m, f.Name()
	}

	// Success path: finalize(true) emits the buffered JSON array.
	m, path := mkModel(t)
	defer func() { _ = os.Remove(path) }()
	m.out.Result("a.example.com", []dns.Record{{Type: "A", Value: "1.2.3.4"}})
	if err := m.finalizeOutput(true); err != nil {
		t.Fatalf("finalizeOutput: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "a.example.com") {
		t.Errorf("expected JSON output after finalize(true), got %q", data)
	}
	if m.out != nil || m.outFile != nil || m.outBuf != nil {
		t.Error("finalizeOutput should clear the output handles")
	}

	// Error path: finalize(false) closes without Finish, so nothing is written.
	m2, path2 := mkModel(t)
	defer func() { _ = os.Remove(path2) }()
	if err := m2.finalizeOutput(false); err != nil {
		t.Fatalf("finalizeOutput: %v", err)
	}
	data2, err := os.ReadFile(path2)
	if err != nil {
		t.Fatal(err)
	}
	if len(data2) != 0 {
		t.Errorf("expected no structured output after finalize(false), got %q", data2)
	}
}

// TestFinalizeOutputNoFile is a no-op safety check: finalizing when no output
// file is configured must not panic.
func TestFinalizeOutputNoFile(t *testing.T) {
	m := &Model{}
	if err := m.finalizeOutput(true); err != nil {
		t.Fatalf("finalizeOutput: %v", err)
	}
	if err := m.finalizeOutput(false); err != nil {
		t.Fatalf("finalizeOutput: %v", err)
	}
}

// TestCtrlCAfterDoneQuits covers #43: Ctrl+C on a finished scan quits instead
// of relabelling it "Aborted".
func TestCtrlCAfterDoneQuits(t *testing.T) {
	m := Model{state: stateScan, scanView: newScanViewModel(80, 24, false)}
	m.scanView.done = true
	next, cmd := m.updateScan(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("expected a quit command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("ctrl+c after done did not quit")
	}
	if next.(Model).scanView.aborted {
		t.Error("finished scan was relabelled as aborted")
	}
}

// TestFinalizeOutputReportsCloseError covers #30 for the TUI: a failure to
// complete the results file is returned instead of being discarded.
func TestFinalizeOutputReportsCloseError(t *testing.T) {
	f, err := os.CreateTemp("", "tui-out-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	buf := bufio.NewWriter(f)
	m := &Model{out: output.NewFile(buf, false, output.FormatText), outBuf: buf, outFile: f}
	m.out.Result("a.example.com", nil)
	// Close the file underneath the writer so the final flush fails.
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.finalizeOutput(true); err == nil {
		t.Fatal("finalizeOutput returned nil although the file was already closed")
	}
}
