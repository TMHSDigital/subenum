// Package tui provides a Bubble Tea terminal UI for subenum.
package tui

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/TMHSDigital/subenum/data"
	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
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
	final   scan.Event // the event that ended the scan, for a saved file's summary (#332)

	// What the Sources and Permute fields add around the scan (#274).
	lookups  []sourceLookup  // the passive sources asked, in order
	cands    *candidates.Set // who proposed each name a source had; nil without sources
	foundBy  map[string]int  // results per source that proposed them
	entries  []string        // the main pass's candidates, not permuted again
	names    []string        // the main pass's results: permutation seeds
	pool     *dns.Pool       // the resolver pool, for the permutation pass too
	deadline time.Time       // Max Duration's end, shared by both passes
	zone     *zoneAnswer     // the Zone Transfer and NSEC Walk answer; nil when neither ran (#418)
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
	// SourceURLs replace the passive sources' endpoints, by source name;
	// tests point them at local servers.
	SourceURLs map[string]string
	// TransferPort is the port zone transfers and the DNSSEC probe go to;
	// "" is 53. Tests point it at a local server.
	TransferPort string
	// Warnings are shown on the form until the first scan starts, such as
	// the flags given with -tui that the form has no field for (#418).
	Warnings []string
}

// New creates the root model starting on the form screen.
func New(opts Options) Model {
	saved, _ := loadSavedConfig()
	form := newFormModel(opts.prefill(saved))
	form.warnings = opts.Warnings
	return Model{
		state: stateForm,
		form:  form,
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
	p := tea.NewProgram(New(opts)) // View asks for the alternate screen
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
	case tea.KeyPressMsg:
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
			m.form.asking = len(vals.sources) > 0 && !vals.Simulate
			m.form.zoning = askingZone(vals)
			// Load the wordlist off the event loop so a large list cannot
			// freeze the UI (#55); beginScan runs when it arrives.
			return m, loadWordlistCmd(vals, m.opts)
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
		return m.beginScan(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	var cmd tea.Cmd
	m.form, cmd = m.form.Update(msg)
	return m, cmd
}

// loadWordlistCmd reads and normalizes the wordlist, builds the resolver
// pool and asks the passive sources, in a tea.Cmd goroutine.
func loadWordlistCmd(vals formValues, o Options) tea.Cmd {
	return func() tea.Msg {
		entries, skipped, err := loadWordlist(vals)
		pool, poolErr := loadPool(vals)
		msg := wordlistLoadedMsg{cfg: vals, entries: entries, skipped: skipped, err: err, pool: pool, poolErr: poolErr}
		// The sources and the name servers are asked only for a scan that
		// will start, and never in simulation mode, which sends nothing off
		// the machine (#274, #418).
		sources := !vals.Simulate && len(vals.sources) > 0
		zone := askingZone(vals)
		if err != nil || poolErr != nil || len(entries) == 0 || !sources && !zone {
			return msg
		}
		ctx := context.Background()
		if vals.nsecWalk && vals.MaxDuration > 0 {
			// Max Duration covers the walk, as -max-duration does (#437).
			msg.deadline = time.Now().Add(vals.MaxDuration)
		}
		// The zone is asked while the sources are, as on the command line
		// (#365); its names are added after theirs.
		var wg sync.WaitGroup
		if zone {
			wg.Go(func() {
				z := askZone(ctx, vals, o, msg.deadline)
				msg.zone = &z
			})
		}
		if sources {
			msg.lookups = fetchSources(ctx, vals.Domain, vals.sources, o)
		}
		wg.Wait()
		// The same candidate set as the command line's (#347).
		msg.cands = candidates.New(vals.Domain, entries, nil)
		for i := range msg.lookups {
			msg.lookups[i].added = msg.cands.Add(msg.lookups[i].Source, msg.lookups[i].Names)
		}
		if z := msg.zone; z != nil {
			// Transferred and walked names are candidates like a source's:
			// each is still looked up (#85, #437).
			if vals.axfr {
				z.addedAXFR = msg.cands.Add(candidates.AXFR, z.Names)
			}
			if vals.nsecWalk {
				z.addedNSEC = msg.cands.Add(candidates.NSEC, z.Walked)
			}
		}
		msg.entries = msg.cands.Entries()
		return msg
	}
}

// askingZone reports whether the scan asks the domain's name servers first:
// Zone Transfer or NSEC Walk is on, outside simulation mode, for a domain
// Exclude does not rule out, which the scan's preflight refuses (#372, #418).
func askingZone(vals formValues) bool {
	return vals.zoneLookup() && !vals.Simulate && !scan.TargetOutOfScope(vals.Exclude, vals.Domain)
}

// loadWordlist reads the file named on the form, or the bundled list when the
// field is empty, the way the CLI treats a missing -w (#288). A file is
// streamed, as the CLI streams -w, rather than held whole in memory (#411).
func loadWordlist(vals formValues) (entries []string, skipped int, err error) {
	pr := wordlist.NewPreparer()
	if vals.wordlist != "" {
		err = wordlist.EachLineOf(vals.wordlist, pr.Add)
	} else {
		err = wordlist.EachLine(strings.NewReader(data.Subdomains5k), pr.Add)
	}
	if err != nil {
		return nil, 0, err
	}
	entries, _, skipped = pr.Prepared().For(vals.Domain)
	return entries, skipped, nil
}

// loadPool builds the resolver pool from the Resolver Pool file, as the CLI
// does for -r (#195). It returns nil without a file, and in simulation mode,
// which sends no DNS queries.
func loadPool(vals formValues) (*dns.Pool, error) {
	if vals.resolvers == "" || vals.Simulate {
		return nil, nil
	}
	lines, err := wordlist.ReadLines(vals.resolvers)
	if err != nil {
		return nil, fmt.Errorf("cannot read resolver pool: %w", err)
	}
	pool, err := dns.NewPoolFromLines(lines, vals.Timeout, vals.RatePerResolver)
	if errors.Is(err, dns.ErrNoResolvers) {
		err = fmt.Errorf("%s %w", vals.resolvers, err)
	}
	if err != nil {
		return nil, fmt.Errorf("resolver pool: %w", err)
	}
	return pool, nil
}

func (m Model) beginScan(loaded wordlistLoadedMsg) (tea.Model, tea.Cmd) {
	vals, entries, skipped, pool := loaded.cfg, loaded.entries, loaded.skipped, loaded.pool
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
		m.out = newFileWriter(f, vals, vals.format, seed)
	}
	m.vals, m.seed, m.started, m.final = vals, seed, time.Now(), scan.Event{}
	m.lookups, m.cands, m.foundBy = loaded.lookups, loaded.cands, map[string]int{}
	m.entries, m.names, m.pool, m.deadline, m.zone = entries, nil, pool, time.Time{}, loaded.zone

	m.state = stateScan
	m.scanView = newScanViewModel(m.width, m.height, vals.Simulate)
	m.scanView.permute = vals.permute
	// Same facts the CLI prints: the seed that reproduces a simulation, and
	// how many wordlist entries were dropped (#80).
	if vals.Simulate {
		m.scanView.seed = seed
	}
	if skipped > 0 {
		m.scanView.addMessage(wildcardStyle.Render(fmt.Sprintf("⚠ Skipped %d invalid wordlist entries (not valid DNS labels, or name longer than 253 characters)", skipped)))
	}

	if vals.resolvers != "" && vals.Simulate {
		m.scanView.addMessage(dimStyle.Render("Note: the resolver pool is ignored in simulation mode, which sends no DNS queries"))
	}

	if len(vals.sources) > 0 && vals.Simulate {
		m.scanView.addMessage(dimStyle.Render("Note: the passive sources are ignored in simulation mode, which sends nothing off the machine"))
	}
	// Same lines as the CLI's: what each source gave, or why the scan runs
	// without its names (#274).
	for _, l := range m.lookups {
		label := passive.Labels[l.Source]
		switch {
		case !l.Fetched:
			m.scanView.addMessage(wildcardStyle.Render(fmt.Sprintf("⚠ %s; scanning without %s names", l.Err, label)))
			continue
		case l.Truncated != "":
			m.scanView.addMessage(wildcardStyle.Render("⚠ " + l.Truncated))
		}
		m.scanView.addMessage(dimStyle.Render(passive.AddedLine(label, len(l.Names), vals.Domain, l.added)))
	}
	if vals.zoneLookup() && vals.Simulate {
		m.scanView.addMessage(dimStyle.Render("Note: Zone Transfer and NSEC Walk are ignored in simulation mode, which sends no DNS queries"))
	}
	// Same lines as the CLI's -axfr and -nsec-walk (#418).
	if z := m.zone; z != nil {
		for _, note := range z.notes {
			style := dimStyle
			if strings.HasPrefix(note, "Warning: ") || strings.HasPrefix(note, "Zone ") {
				style = wildcardStyle // a failure, or a zone anyone can list
			}
			m.scanView.addMessage(style.Render(note))
		}
		if vals.axfr && len(z.Allowed) > 0 {
			m.scanView.addMessage(dimStyle.Render(passive.AddedLine("Zone transfer", len(z.Names), vals.Domain, z.addedAXFR)))
		}
		if vals.nsecWalk && len(z.Walked) > 0 {
			m.scanView.addMessage(dimStyle.Render(passive.AddedLine("NSEC walk", len(z.Walked), vals.Domain, z.addedNSEC)))
		}
	}

	// Same notice as the CLI's, so the TUI user knows which list ran (#288).
	if vals.wordlist == "" {
		m.scanView.addMessage(dimStyle.Render("Note: empty wordlist field: using the bundled top-5000 list (SecLists)"))
	}

	opts := vals.options(entries, seed)
	opts.Pool = pool
	if vals.MaxDuration > 0 {
		// The budget starts with the scan, as -max-duration's starts when the
		// CLI's scans do (#274), or with the NSEC walk before it (#418).
		m.deadline = loaded.deadline
		if m.deadline.IsZero() {
			m.deadline = time.Now().Add(vals.MaxDuration)
		}
		opts.Deadline = m.deadline
	}
	cfg := opts.Config

	// Persist form values for next session (best-effort).
	_ = saveConfig(vals.saved)

	events := make(chan scan.Event, 128)
	m.events = events
	go scan.Run(ctx, cfg, events)

	return m, listenForEvents(events)
}

// newFileWriter returns a writer for a results file in the same shape as the
// CLI's: a takeover column when CNAME records are requested (#118), and with
// sources or a permutation pass, what proposed each result (#274).
func newFileWriter(f *output.File, vals formValues, format output.Format, seed uint64) *output.Writer {
	w := output.NewFile(f.Writer, vals.Simulate, format)
	w.SetSeed(seed)
	w.SetTakeoverColumn(dns.HintsTakeover(vals.Types))
	w.SetSourcesColumn(vals.attributed())
	return w
}

func (m Model) updateScan(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		// The save prompt (#332) takes every key but ctrl+c while it is open.
		if m.scanView.saving && msg.String() != "ctrl+c" {
			if m.scanView.handleSaveKey(msg) {
				m.saveResults(expandHome(strings.TrimSpace(m.scanView.savePath)))
			}
			return m, nil
		}
		// The result filter (#221) takes its keys first; while it is being
		// typed it takes every key but ctrl+c, so q and r can be typed.
		if m.scanView.handleFilterKey(msg) {
			return m, nil
		}
		switch msg.String() {
		case "s":
			if m.scanView.done {
				m.scanView.saving = true
				m.scanView.overwritePath = ""
				if m.scanView.savePath == "" {
					m.scanView.savePath = m.defaultSavePath()
				}
			}
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
				// No size message follows, and the form scrolls by it (#287).
				m.form.width, m.form.height = m.width, m.height
				m.events = nil
				return m, m.form.initCmd()
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case permutationReadyMsg:
		return m.beginPermutation(msg)
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
	case ev.Kind == scan.EventDone && !m.scanView.done:
		// The main pass finished and a permutation pass follows (#274): its
		// candidates are built off the event loop, and beginPermutation runs
		// when they arrive.
		return m, tea.Batch(svCmd, permutationCmd(m.vals.Domain, m.entries, m.names, m.cands))
	case ev.Kind == scan.EventDone && ev.Stopped && m.scanView.main == nil:
		// The scan stopped before testing candidates (an early error such as a
		// wildcard zone without Force, #99): close the file without finalizing,
		// mirroring the CLI, which skips Finish so no empty JSON array is written.
		m.final = ev.Event
		m.reportOutputErr(m.finalizeOutput(false))
		// The CLI writes its -stats file for a run that stopped early too.
		m.writeStats(m.summary(ev.Event))
		return m, svCmd
	case ev.Kind == scan.EventDone:
		// Successful completion (including user abort, which still drains and
		// emits EventDone): finalize structured output to close the streamed JSON
		// array and flush CSV and partial results. A JSONL file ends with the
		// run-quality summary, as the CLI's does (#118). A permutation pass
		// that stopped early still leaves the main pass's results to write.
		m.finishOutput(ev.Event)
		return m, svCmd
	case ev.Kind == scan.EventResult:
		m.record(ev.Result)
	}
	// A kind this view does not know yet must not stall the scan: the
	// listener is re-armed for it like any other event (#165).
	return m, tea.Batch(svCmd, listenForEvents(m.events))
}

// record keeps a result for the permutation pass's seeds and writes it to
// the output file, saying what proposed it when the scan has sources or a
// permutation pass (#274).
func (m *Model) record(r scan.Result) {
	res := output.Result{Result: r}
	switch permuting := m.scanView.main != nil; {
	case permuting:
		res.Permutation, res.Sources = true, candidates.FromPermute
	case m.vals.attributed():
		res.Sources = m.cands.SourcesOf(r.Subdomain)
		if m.vals.permute {
			m.names = append(m.names, r.Subdomain)
		}
	}
	for _, src := range res.Sources {
		m.foundBy[src]++
	}
	// The scan view has just added this result as its last line; keep what
	// proposed it there too, so a saved file says so (#332).
	if n := len(m.scanView.results); n > 0 {
		m.scanView.results[n-1].res = res
	}
	if m.out != nil {
		m.out.Emit(res)
	}
}

// beginPermutation starts the permutation pass over the candidates built
// from the main pass's results: a second scan with the same settings, one
// level deep. With nothing to scan, or after ctrl+c, the scan ends here.
func (m Model) beginPermutation(msg permutationReadyMsg) (tea.Model, tea.Cmd) {
	sv := &m.scanView
	if sv.main == nil || sv.done {
		return m, nil
	}
	if msg.seeds > 0 {
		sv.perm = &permutationPass{seeds: msg.seeds, candidates: len(msg.candidates)}
	}
	if len(msg.candidates) == 0 || sv.aborted {
		sv.done = true
		m.finishOutput(*sv.main)
		return m, nil
	}
	if msg.tooLong > 0 {
		sv.addMessage(dimStyle.Render(fmt.Sprintf("Permutation pass: skipped %d candidates longer than 253 characters", msg.tooLong)))
	}
	sv.addMessage(dimStyle.Render(fmt.Sprintf("Permutation pass: %d candidates from %d seed names", len(msg.candidates), msg.seeds)))
	sv.processed, sv.total, sv.eta, sv.etaText = 0, int64(len(msg.candidates)), nil, ""

	// Under Recursive, children of a found permutation would be built from
	// the candidate list itself, so the pass is flat, as the CLI's is (#111).
	opts := m.vals.options(msg.candidates, m.seed)
	opts.Recursive, opts.Depth = false, 1
	opts.Pool, opts.Deadline = m.pool, m.deadline

	ctx, cancel := context.WithCancel(context.Background())
	if m.cancel != nil {
		m.cancel() // the main pass's context; it has ended
	}
	m.cancel = cancel
	events := make(chan scan.Event, 128)
	m.events = events
	go scan.Run(ctx, opts.Config, events)
	return m, listenForEvents(events)
}

// finishOutput writes the run-quality summary and closes the output file
// once the scan, with its permutation pass if it has one, has ended. final
// is the event that ended it.
func (m *Model) finishOutput(final scan.Event) {
	if main := m.scanView.main; main != nil {
		final = *main // the report's counts are the main pass's (#298)
	}
	m.final = final
	summary := m.summary(final)
	if m.out != nil {
		m.out.Summary(summary)
	}
	m.reportOutputErr(m.finalizeOutput(true))
	m.writeStats(summary)
}

// writeStats writes the run-quality report to the Stats File, if one is
// set, as -stats does (#418). A failure is reported on the scan screen and
// fails the run, as the CLI's does.
func (m *Model) writeStats(summary output.Summary) {
	if m.vals.statsFile == "" {
		return
	}
	if err := output.WriteSummaryFile(m.vals.statsFile, summary); err != nil {
		m.scanView.outputErr = true
		m.scanView.addMessage(errorStyle.Render("✗ cannot write the stats file: " + err.Error()))
		return
	}
	m.scanView.addMessage(dimStyle.Render("Wrote the run-quality report to " + m.vals.statsFile))
}

// defaultSavePath is the save prompt's starting path: the form's Output
// file if it had one, else subenum-<domain> with the form's format's
// extension (#332).
func (m *Model) defaultSavePath() string {
	if m.vals.outputFile != "" {
		return m.vals.outputFile
	}
	ext := map[output.Format]string{output.FormatJSON: ".json", output.FormatJSONL: ".jsonl", output.FormatCSV: ".csv"}[m.vals.format]
	if ext == "" {
		ext = ".txt"
	}
	return "subenum-" + m.vals.Domain + ext
}

// saveFormat picks a saved file's format from its extension, falling back
// to the form's Format for any other name (#332).
func saveFormat(path string, fallback output.Format) output.Format {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".txt":
		return output.FormatText
	case ".json":
		return output.FormatJSON
	case ".jsonl", ".ndjson":
		return output.FormatJSONL
	case ".csv":
		return output.FormatCSV
	}
	return fallback
}

// saveResults writes the results the filter shows to path, in the format its
// extension names, the way the Output file would have (#332). A text file
// carries each result's records while the records view is on, as with
// -show-records. The outcome is a notice on the scan screen; a failed save
// leaves an existing file unchanged and does not change the exit code.
func (m *Model) saveResults(path string) {
	sv := &m.scanView
	if _, err := os.Lstat(path); err == nil && sv.overwritePath != path {
		// The viewport may be filtered or have discarded earlier results.
		// Never replace an existing file on the first Enter (#360).
		sv.saving, sv.overwritePath = true, path
		return
	}
	sv.overwritePath = ""
	results := sv.toSave()
	format := saveFormat(path, m.vals.format)
	err := func() error {
		f, err := output.CreateFile(path)
		if err != nil {
			return err
		}
		w := newFileWriter(f, m.vals, format, m.seed)
		w.SetShowRecords(sv.records)
		for _, r := range results {
			w.Emit(r)
		}
		w.Summary(m.summary(m.final))
		err = w.Finish()
		if cerr := f.Close(err == nil); err == nil {
			err = cerr
		}
		return err
	}()
	if err != nil {
		sv.addMessage(errorStyle.Render("✗ cannot save results: " + err.Error()))
		return
	}
	text := fmt.Sprintf("Saved %d results to %s", len(results), path)
	if sv.filtered() {
		text += fmt.Sprintf(" (the %d of %d the filter shows)", len(results), len(sv.results))
	}
	if sv.dropped > 0 {
		text += fmt.Sprintf("; %d earlier results were no longer kept", sv.dropped)
	}
	sv.addMessage(dimStyle.Render(text))
}

// finalizeOutput closes the optional output file. When finish is true the
// structured writer is finalized first (streamed JSON array closed, CSV
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
	status := report.StatusOK
	switch {
	case m.scanView.failed():
		status = report.StatusFailed
	case m.scanView.aborted:
		status = report.StatusInterrupted
	}
	t := report.Target(m.vals.Domain, status, "", true, final, settingLabel)
	lookups := make([]passive.Lookup, len(m.lookups))
	for i, l := range m.lookups {
		lookups[i] = l.Lookup
	}
	report.Sources(&t, lookups, m.foundBy)
	if z := m.zone; z != nil {
		// The same zone fields as the CLI's report (#85, #234, #437).
		t.AXFRAllowed, t.AXFRNames, t.AXFRError = z.Allowed, len(z.Names), z.Err
		t.AXFRFound = m.foundBy[candidates.AXFR]
		t.NSECNames, t.NSECStop = len(z.Walked), z.WalkStop
		t.NSECFound = m.foundBy[candidates.NSEC]
		t.ZoneDenial = string(z.Denial)
		t.QueriesSent += z.Queries
	}
	m.scanView.perm.summarize(&t, m.scanView.aborted, m.scanView.errText)
	// As the CLI's, with the resolver pool's accounting (#367).
	return report.Build(report.Run{
		Version:   m.opts.Version,
		Started:   m.started,
		Simulated: m.vals.Simulate,
		Seed:      m.seed,
		Resolver:  dns.DisplayServer(m.vals.DNSServer),
		RateLimit: m.vals.Rate,
	}, []output.TargetSummary{t}, m.pool, time.Since(m.started))
}

// reportOutputErr surfaces an output-file failure in the scan view.
func (m *Model) reportOutputErr(err error) {
	if err != nil {
		m.scanView.outputErr = true
		m.scanView.addMessage(errorStyle.Render("✗ output file incomplete: " + err.Error()))
	}
}

// View satisfies tea.Model. The TUI runs on the alternate screen.
func (m Model) View() tea.View {
	v := tea.NewView(m.content())
	v.AltScreen = true
	return v
}

// content renders the current screen.
func (m Model) content() string {
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
