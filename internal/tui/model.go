// Package tui provides a Bubble Tea terminal UI for subenum.
package tui

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/report"
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
	outFile *output.File

	opts    Options
	vals    formValues // the running scan's settings, for its report
	seed    uint64
	started time.Time
}

// Options configure the TUI.
type Options struct {
	// Version is reported in the run-quality summary.
	Version string
	// Settings are flag values from the command line, SUBENUM_* variables or
	// the config file, keyed by flag name. They pre-fill the form over its
	// remembered values, as they override built-in defaults on the command
	// line (#118, #195).
	Settings map[string]string
	// Domain is the domain argument given with -tui; it pre-fills the
	// Domain field when set (#195).
	Domain string
}

// New creates the root model starting on the form screen.
func New(opts Options) Model {
	saved, _ := loadSavedConfig()
	return Model{
		state: stateForm,
		form:  newFormModel(opts.prefill(saved)),
		opts:  opts,
	}
}

// prefill overlays the launch options on the remembered form values.
func (o Options) prefill(saved savedConfig) savedConfig {
	sc := withSettings(saved, o.Settings)
	if o.Domain != "" {
		sc.Domain = o.Domain
	}
	return sc
}

// Start runs the TUI and returns an exit code: 1 if the TUI itself failed,
// the last scan failed (#55) or its results file could not be written
// (#155), else 0.
func Start(opts Options) int {
	p := tea.NewProgram(New(opts), tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		return 1
	}
	return exitCode(final)
}

// exitCode maps the final model to the process exit code.
func exitCode(final tea.Model) int {
	if m, ok := final.(Model); ok && (m.scanView.failed() || m.scanView.outputErr) {
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
			if m.form.loading {
				return m, nil
			}
			vals, errStr := m.form.validate()
			if errStr != "" {
				m.form.err = errStr
				return m, nil
			}
			m.form.err = ""
			m.form.loading = true
			// Load the wordlist off the event loop so a large list cannot
			// freeze the UI (#55); beginScan runs when it arrives.
			return m, loadWordlistCmd(vals)
		}

	case wordlistLoadedMsg:
		m.form.loading = false
		if msg.err != nil {
			m.form.err = "cannot read wordlist: " + msg.err.Error()
			return m, nil
		}
		if len(msg.entries) == 0 {
			m.form.err = "wordlist has no valid entries"
			return m, nil
		}
		if msg.poolErr != nil {
			m.form.err = msg.poolErr.Error()
			return m, nil
		}
		return m.beginScan(msg.cfg, msg.entries, msg.skipped, msg.pool)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	var cmd tea.Cmd
	m.form, cmd = m.form.Update(msg)
	return m, cmd
}

// loadWordlistCmd reads and normalizes the wordlist, and builds the resolver
// pool, in a tea.Cmd goroutine.
func loadWordlistCmd(vals formValues) tea.Cmd {
	return func() tea.Msg {
		entries, _, skipped, err := wordlist.LoadWordlist(vals.wordlist, vals.domain)
		pool, poolErr := loadPool(vals)
		return wordlistLoadedMsg{cfg: vals, entries: entries, skipped: skipped, err: err, pool: pool, poolErr: poolErr}
	}
}

// loadPool builds the resolver pool from the Resolver Pool file, as the CLI
// does for -r (#195). It returns nil without a file, and in simulation mode,
// which sends no DNS queries.
func loadPool(vals formValues) (*dns.Pool, error) {
	if vals.resolvers == "" || vals.simulate {
		return nil, nil
	}
	lines, err := wordlist.ReadLines(vals.resolvers)
	if err != nil {
		return nil, fmt.Errorf("cannot read resolver pool: %w", err)
	}
	addrs, err := dns.ParseResolverList(lines)
	if err == nil && len(addrs) == 0 {
		err = fmt.Errorf("%s lists no resolvers", vals.resolvers)
	}
	if err != nil {
		return nil, fmt.Errorf("resolver pool: %w", err)
	}
	pool := dns.NewPool(addrs, time.Duration(vals.timeoutMs)*time.Millisecond)
	pool.SetRatePerResolver(vals.ratePerResolver)
	return pool, nil
}

func (m Model) beginScan(vals formValues, entries []string, skipped int, pool *dns.Pool) (tea.Model, tea.Cmd) {
	// Create the context up front so cancel is always assigned to the model
	// before any early return. This satisfies static analysis tools that
	// require the cancellation function to be demonstrably reachable.
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	seed := rand.Uint64()

	// Open the optional output file before switching screens so a create error
	// is reported on the form rather than mid-scan.
	if vals.outputFile != "" {
		f, ferr := output.CreateFile(vals.outputFile)
		if ferr != nil {
			cancel()
			m.form.err = "cannot create output file: " + ferr.Error()
			return m, nil
		}
		m.outFile = f
		m.out = output.NewFile(f.Writer, vals.simulate, vals.format)
		m.out.SetSeed(seed)
		// Same file shape as the CLI's: a takeover column when CNAME
		// records are requested (#118).
		m.out.SetTakeoverColumn(slices.Contains(vals.recordTypes, "CNAME"))
		m.out.SetInternalColumn(slices.Contains(vals.recordTypes, "A") || slices.Contains(vals.recordTypes, "AAAA"))
	}
	m.vals, m.seed, m.started = vals, seed, time.Now()

	m.state = stateScan
	m.scanView = newScanViewModel(m.width, m.height, vals.simulate)
	m.scanView.noAbort = vals.noAbort
	// Same facts the CLI prints: the seed that reproduces a simulation, and
	// how many wordlist entries were dropped (#80).
	if vals.simulate {
		m.scanView.seed = seed
	}
	if skipped > 0 {
		m.scanView.addMessage(wildcardStyle.Render(fmt.Sprintf("⚠ Skipped %d invalid wordlist entries (not valid DNS labels, or name longer than 253 characters)", skipped)))
	}

	if vals.resolvers != "" && vals.simulate {
		m.scanView.addMessage(dimStyle.Render("Note: the resolver pool is ignored in simulation mode, which sends no DNS queries"))
	}

	opts := vals.options(entries, seed)
	opts.Pool = pool
	cfg := opts.Config()

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
			// Once the scan has finished there is nothing to abort; quit
			// instead of relabelling a completed scan as "Aborted" (#43).
			if m.scanView.done {
				return m, tea.Quit
			}
			if m.cancel != nil {
				m.cancel()
			}
			// Mark the scan as aborted so the upcoming EventDone (scan.Run still
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
				// Defensive: the output file is normally closed on EventDone, but
				// make sure it is not left open before starting a new scan.
				_ = m.finalizeOutput(false)
				// Restore the values just scanned so the user doesn't re-type
				// everything. They already include the launch options, which
				// are not applied again: that would undo edits made on the
				// form (#195).
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
	ev, ok := msg.(eventMsg)
	if !ok {
		return m, svCmd
	}
	switch {
	case ev.Kind == scan.EventDone && ev.Stopped:
		// The scan stopped before testing candidates (an early error such as a
		// wildcard zone without Force, #99): close the file without finalizing,
		// mirroring the CLI, which skips Finish so no empty JSON array is written.
		m.reportOutputErr(m.finalizeOutput(false))
		return m, svCmd
	case ev.Kind == scan.EventDone:
		// Successful completion (including user abort, which still drains and
		// emits EventDone): finalize structured output so buffered JSON/CSV is
		// written and partial results are flushed. A JSONL file ends with the
		// run-quality summary, as the CLI's does (#118).
		if m.out != nil {
			m.out.Summary(m.summary(ev.Event))
		}
		m.reportOutputErr(m.finalizeOutput(true))
		return m, svCmd
	case ev.Kind == scan.EventResult && m.out != nil:
		m.out.Emit(output.Result{Result: ev.Result})
	}
	// A kind this view does not know yet must not stall the scan: the
	// listener is re-armed for it like any other event (#165).
	return m, tea.Batch(svCmd, listenForEvents(m.events))
}

// finalizeOutput closes the optional output file. When finish is true the
// structured writer is finalized first (buffered JSON array emitted, CSV
// flushed) and the file replaces any existing one; when false it is discarded
// and an existing results file is left untouched (#52).
// Safe to call when no output file is configured.
// It returns the first write, flush, or close error so the scan view can tell
// the user the results file is incomplete.
func (m *Model) finalizeOutput(finish bool) error {
	if m.out == nil {
		return nil
	}
	var firstErr error
	keep := func(err error) {
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}
	if finish {
		keep(m.out.Finish())
	}
	if m.outFile != nil {
		keep(m.outFile.Close(finish))
	}
	m.out = nil
	m.outFile = nil
	return firstErr
}

// summary builds the run-quality report for the finished scan.
func (m *Model) summary(final scan.Event) output.Summary {
	s := report.New(report.Run{
		Version:   m.opts.Version,
		Started:   m.started,
		Simulated: m.vals.simulate,
		Seed:      m.seed,
		Resolver:  m.vals.dnsServer,
		RateLimit: m.vals.rate,
	})
	status := "ok"
	switch {
	case m.scanView.failed():
		status = "failed"
	case m.scanView.aborted:
		status = "interrupted"
	}
	report.Finish(&s, []output.TargetSummary{report.Target(m.vals.domain, status, "", true, final, settingLabel)}, time.Since(m.started))
	return s
}

// reportOutputErr surfaces an output-file failure in the scan view.
func (m *Model) reportOutputErr(err error) {
	if err != nil {
		m.scanView.outputErr = true
		m.scanView.addMessage(errorStyle.Render("✗ output file incomplete: " + err.Error()))
	}
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

// listenForEvents returns a tea.Cmd that delivers the next scan.Event as an
// eventMsg.
func listenForEvents(events <-chan scan.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-events
		if !ok {
			// scan.Run always sends EventDone before closing (#99), and the
			// listener is not re-armed after it; a closed channel is defensive.
			return eventMsg{scan.Event{Kind: scan.EventDone, Stopped: true}}
		}
		return eventMsg{ev}
	}
}

// eventMsg carries one engine event into Bubble Tea (#162).
type eventMsg struct{ scan.Event }
