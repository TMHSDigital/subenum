package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
)

// TestFinalizeOutputGatesStructuredOutput locks in the TUI's replication of the
// CLI contract: structured output is finalized only on the success path
// (doneMsg -> finalizeOutput(true)). The early-error path
// (abortedMsg -> finalizeOutput(false)) must not emit an empty JSON array, the
// bug fixed once for the CLI in main.run, and must leave an existing results
// file untouched (#52).
func TestFinalizeOutputGatesStructuredOutput(t *testing.T) {
	mkModel := func(t *testing.T, path string) *Model {
		t.Helper()
		f, err := output.CreateFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return &Model{
			out:     output.NewFile(f.Writer, false, output.FormatJSON),
			outFile: f,
		}
	}
	dir := t.TempDir()

	// Success path: finalize(true) emits the buffered JSON array.
	path := filepath.Join(dir, "ok.json")
	m := mkModel(t, path)
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
	if m.out != nil || m.outFile != nil {
		t.Error("finalizeOutput should clear the output handles")
	}

	// Error path: finalize(false) discards the run and keeps the old file.
	path2 := filepath.Join(dir, "prev.json")
	if err := os.WriteFile(path2, []byte("PREVIOUS RESULTS"), 0o644); err != nil {
		t.Fatal(err)
	}
	m2 := mkModel(t, path2)
	m2.out.Result("b.example.com", nil)
	if err := m2.finalizeOutput(false); err != nil {
		t.Fatalf("finalizeOutput: %v", err)
	}
	data2, err := os.ReadFile(path2)
	if err != nil {
		t.Fatal(err)
	}
	if string(data2) != "PREVIOUS RESULTS" {
		t.Errorf("existing file changed after finalize(false): %q", data2)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
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
	path := filepath.Join(t.TempDir(), "out.txt")
	f, err := output.CreateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := &Model{out: output.NewFile(f.Writer, false, output.FormatText), outFile: f}
	m.out.Result("a.example.com", nil)
	// Put a non-empty directory where the results file goes, so the final
	// rename into place fails.
	if err := os.MkdirAll(filepath.Join(path, "blocker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.finalizeOutput(true); err == nil {
		t.Fatal("finalizeOutput returned nil although the results file could not be written")
	}
}

// TestValidateRejectsStdinWordlist covers #55: "-" would read the stdin that
// Bubble Tea owns and freeze the UI.
func TestValidateRejectsStdinWordlist(t *testing.T) {
	m := newFormModel(savedConfig{})
	m.inputs[0].SetValue("example.com")
	m.inputs[1].SetValue("-")
	if _, errStr := m.validate(); !strings.Contains(errStr, "standard input") {
		t.Fatalf("validate() error = %q, want a standard-input rejection", errStr)
	}
}

// TestRunLoadsWordlistAsync covers #55: ctrl+r returns immediately with the
// wordlist load deferred to a tea.Cmd, and the loaded message starts the scan.
func TestRunLoadsWordlistAsync(t *testing.T) {
	redirectConfig(t) // beginScan saves the form values
	wl := filepath.Join(t.TempDir(), "wl.txt")
	if err := os.WriteFile(wl, []byte("www\nmail\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := Model{state: stateForm, form: newFormModel(savedConfig{})}
	m.form.inputs[0].SetValue("example.com")
	m.form.inputs[1].SetValue(wl)
	m.form.inputs[10].SetValue("") // no output file
	m.form.toggles[0] = true       // simulate: the started scan sends no DNS traffic

	next, cmd := m.updateForm(tea.KeyMsg{Type: tea.KeyCtrlR})
	nm := next.(Model)
	if nm.form.err != "" {
		t.Fatalf("form error: %s", nm.form.err)
	}
	if !nm.form.loading || nm.state != stateForm || cmd == nil {
		t.Fatalf("loading=%v state=%v cmd=%v, want a pending load on the form", nm.form.loading, nm.state, cmd != nil)
	}
	if !strings.Contains(nm.form.View(), "Loading wordlist") {
		t.Error("form does not show the loading state")
	}
	// A second ctrl+r while loading is ignored.
	if _, again := nm.updateForm(tea.KeyMsg{Type: tea.KeyCtrlR}); again != nil {
		t.Error("ctrl+r during load started a second load")
	}

	loaded, ok := cmd().(wordlistLoadedMsg)
	if !ok || loaded.err != nil || len(loaded.entries) != 2 {
		t.Fatalf("load result = %+v", loaded)
	}
	started, _ := nm.updateForm(loaded)
	sm := started.(Model)
	defer sm.cancel()
	if sm.state != stateScan || sm.form.loading {
		t.Fatalf("state=%v loading=%v after load, want the scan screen", sm.state, sm.form.loading)
	}
}

// TestScanFailureStatusAndExitCode covers #55: a scan that ends with an error
// shows "Failed", not "Aborted", and the TUI exits non-zero.
func TestScanFailureStatusAndExitCode(t *testing.T) {
	update := func(sv scanViewModel, msgs ...tea.Msg) scanViewModel {
		for _, msg := range msgs {
			sv, _ = sv.Update(msg)
		}
		return sv
	}

	// Preflight failure: error, then the channel closes without EventDone.
	sv := update(newScanViewModel(120, 40, false), errorMsg{text: "resolver failed preflight"}, abortedMsg{})
	if !sv.failed() || !strings.Contains(sv.View(), "Failed: resolver failed preflight") || strings.Contains(sv.View(), "Aborted") {
		t.Errorf("preflight failure not shown as Failed:\n%s", sv.View())
	}
	if code := exitCode(Model{scanView: sv}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}

	// Reliability warning under -no-abort with a finished scan is not a failure.
	nv := newScanViewModel(120, 40, false)
	nv.noAbort = true
	nv = update(nv, errorMsg{text: "warning: 30% failed"}, doneMsg{processed: 5, total: 5})
	if nv.failed() || exitCode(Model{scanView: nv}) != 0 {
		t.Error("-no-abort warning counted as a failure")
	}

	// A user abort stays "Aborted" and exits 0.
	av := newScanViewModel(120, 40, false)
	av.aborted = true
	av = update(av, doneMsg{processed: 1, total: 5})
	if av.failed() || !strings.Contains(av.View(), "Aborted") || exitCode(Model{scanView: av}) != 0 {
		t.Errorf("user abort mis-rendered:\n%s", av.View())
	}
}
