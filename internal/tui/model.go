// Package tui provides a Bubble Tea terminal UI for subenum.
package tui

import (
	"bufio"
	"context"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

type appState int

const (
	stateForm appState = iota
	stateScan
)

// Model is the root Bubble Tea model.
type Model struct {
	state    appState
	form     formModel
	scanView scanViewModel
	cancel   context.CancelFunc
	events   <-chan scan.Event
	width    int
	height   int

	// Optional structured output file. The viewport stays human-readable; these
	// mirror resolved records to disk in the chosen format when an output file
	// is configured on the form.
	out     *output.Writer
	outBuf  *bufio.Writer
	outFile *os.File
}

// New creates the root model starting on the form screen.
func New() Model {
	saved, _ := loadSavedConfig()
	return Model{
		state: stateForm,
		form:  newFormModel(saved),
	}
}

// Start runs the TUI and returns an exit code (0 = ok, 1 = error).
func Start() int {
	p := tea.NewProgram(New(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return 1
	}
	return 0
}

// Init satisfies tea.Model.
func (m Model) Init() tea.Cmd {
	// Kick off cursor blink for the initially focused form field.
	return m.form.initCmd()
}

// Update satisfies tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.state {
	case stateForm:
		return m.updateForm(msg)
	case stateScan:
		return m.updateScan(msg)
	}
	return m, nil
}

func (m Model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit

		case "ctrl+r":
			vals, errStr := m.form.validate()
			if errStr != "" {
				m.form.err = errStr
				return m, nil
			}
			m.form.err = ""
			// Kick off the scan.
			return m, func() tea.Msg { return startScanMsg{cfg: vals} }
		}

	case startScanMsg:
		return m.beginScan(msg.cfg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	var cmd tea.Cmd
	m.form, cmd = m.form.Update(msg)
	return m, cmd
}

func (m Model) beginScan(vals formValues) (tea.Model, tea.Cmd) {
	// Create the context up front so cancel is always assigned to the model
	// before any early return. This satisfies static analysis tools that
	// require the cancellation function to be demonstrably reachable.
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	entries, _, err := wordlist.LoadWordlist(vals.wordlist)
	if err != nil {
		cancel() // explicitly cancel before returning on error
		m.form.err = "cannot read wordlist: " + err.Error()
		return m, nil
	}

	// Open the optional output file before switching screens so a create error
	// is reported on the form rather than mid-scan.
	if vals.outputFile != "" {
		f, ferr := os.Create(vals.outputFile)
		if ferr != nil {
			cancel()
			m.form.err = "cannot create output file: " + ferr.Error()
			return m, nil
		}
		m.outFile = f
		m.outBuf = bufio.NewWriter(f)
		m.out = output.NewFile(m.outBuf, vals.simulate, vals.format)
	}

	m.state = stateScan
	m.scanView = newScanViewModel(m.width, m.height, vals.simulate)

	cfg := scan.Config{
		Domain:      vals.domain,
		Entries:     entries,
		Concurrency: vals.concurrency,
		Timeout:     time.Duration(vals.timeoutMs) * time.Millisecond,
		DNSServer:   vals.dnsServer,
		Simulate:    vals.simulate,
		HitRate:     vals.hitRate,
		Attempts:    vals.attempts,
		Force:       vals.force,
		Types:       vals.recordTypes,
		Recursive:   vals.recursive,
		Depth:       vals.depth,
		Rate:        vals.rate,
	}

	// Persist form values for next session (best-effort).
	_ = saveConfig(vals)

	events := make(chan scan.Event, 128)
	m.events = events
	go scan.Run(ctx, cfg, events)

	return m, listenForEvents(events)
}

func (m Model) updateScan(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			// Mark the scan as aborted so the upcoming doneMsg (scan.Run still
			// drains and emits EventDone) renders the "Aborted" status line.
			m.scanView.aborted = true
		case "q":
			if m.scanView.done {
				return m, tea.Quit
			}
		case "r":
			if m.scanView.done {
				if m.cancel != nil {
					m.cancel()
				}
				// Defensive: the output file is normally closed on doneMsg, but
				// make sure it is not left open before starting a new scan.
				m.finalizeOutput(false)
				// Restore last-used values so the user doesn't re-type everything.
				saved, _ := loadSavedConfig()
				m.state = stateForm
				m.form = newFormModel(saved)
				m.events = nil
				return m, m.form.initCmd()
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	var svCmd tea.Cmd
	m.scanView, svCmd = m.scanView.Update(msg)

	// After each scan event, re-register the listener so the next event is
	// consumed. Stop listening once the scan is done.
	switch msg := msg.(type) {
	case resultMsg:
		if m.out != nil {
			m.out.Result(msg.domain, msg.records)
		}
		return m, tea.Batch(svCmd, listenForEvents(m.events))
	case progressMsg, wildcardMsg, errorMsg:
		return m, tea.Batch(svCmd, listenForEvents(m.events))
	case doneMsg:
		// Successful completion (including user abort, which still drains and
		// emits EventDone): finalize structured output so buffered JSON/CSV is
		// written and partial results are flushed.
		m.finalizeOutput(true)
		return m, svCmd
	case abortedMsg:
		// Channel closed without EventDone (early error such as wildcard without
		// -force): close the file without finalizing, mirroring the CLI which
		// skips Finish on the error path to avoid an empty JSON array.
		m.finalizeOutput(false)
		return m, svCmd
	}

	return m, svCmd
}

// finalizeOutput closes the optional output file. When finish is true the
// structured writer is finalized first (buffered JSON array emitted, CSV
// flushed); when false the file is closed without emitting structured output.
// Safe to call when no output file is configured.
func (m *Model) finalizeOutput(finish bool) {
	if m.out == nil {
		return
	}
	if finish {
		m.out.Finish()
	}
	if m.outBuf != nil {
		_ = m.outBuf.Flush()
	}
	if m.outFile != nil {
		_ = m.outFile.Close()
	}
	m.out = nil
	m.outBuf = nil
	m.outFile = nil
}

// View satisfies tea.Model.
func (m Model) View() string {
	switch m.state {
	case stateForm:
		return m.form.View()
	case stateScan:
		return m.scanView.View()
	}
	return ""
}

// listenForEvents returns a tea.Cmd that drains the events channel,
// converting each scan.Event into the appropriate tea.Msg.
func listenForEvents(events <-chan scan.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-events
		if !ok {
			return abortedMsg{}
		}
		switch ev.Kind {
		case scan.EventResult:
			return resultMsg{domain: ev.Domain, records: ev.Records}
		case scan.EventProgress:
			return progressMsg{processed: ev.Processed, total: ev.Total, found: ev.Found}
		case scan.EventWildcard:
			return wildcardMsg{text: ev.Message}
		case scan.EventError:
			return errorMsg{text: ev.Message}
		case scan.EventDone:
			return doneMsg{processed: ev.Processed, total: ev.Total, found: ev.Found}
		}
		return nil
	}
}
