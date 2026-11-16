package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/report"
	"github.com/TMHSDigital/subenum/internal/scan"
)

var (
	resultStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	headerStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	summaryStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220"))
	wildcardStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
)

const (
	// chromeLines is the fixed layout around the viewport: logo (2), header
	// and blank line (2), progress bar (1), the done-state verdict and
	// counters (2), and the key hint with its top margin (2).
	chromeLines = 9
	// maxShownMessages caps the notices rendered above the viewport; older
	// ones collapse into a "+N earlier" line so the layout cannot overflow.
	maxShownMessages = 3
	// maxResultLines bounds the viewport buffer. The full result set still
	// goes to the output file when one is configured; a save after the scan
	// (#332) writes the results still held.
	maxResultLines = 10000
	// liveRefreshLimit is how many results are re-rendered on every event;
	// past it, content refreshes on progress ticks and at the end, so render
	// cost per result stays constant on large scans.
	liveRefreshLimit = 200
)

// resultLine is one result in the viewport buffer: its rendered line, what
// the filter matches on (#221), and the result itself, for the records view
// and for saving the results after the scan (#332).
type resultLine struct {
	name     string
	takeover bool
	line     string
	res      output.Result
}

// scanViewModel is the live-results screen.
type scanViewModel struct {
	viewport viewport.Model
	progress progress.Model
	results  []resultLine
	dropped  int // results evicted from the viewport buffer
	// The result filter (#221): / starts typing a name filter, enter keeps
	// it, esc clears it; t shows takeover candidates only.
	filter       string
	typing       bool
	takeoverOnly bool
	shown        int      // results the filter lets through, for the status line
	dirty        bool     // results changed since the last SetContent
	messages     []string // wildcard / error messages
	processed    int64
	total        int64
	found        int64
	stats        scan.Stats
	done         bool
	aborted      bool   // the user pressed ctrl+c
	stopped      bool   // the scan stopped before testing candidates (preflight, wildcard abort, #99)
	errText      string // first scan error; the reason shown for a failed scan
	scanFailed   bool   // a pass's EventDone said it failed (#308)
	outputErr    bool   // the results file could not be written in full (#155)
	width        int
	height       int
	simMode      bool
	seed         uint64 // simulation seed, shown so a TUI run can be reproduced

	// v shows each result's records under its line; on the finished screen
	// s opens the save prompt with a default path, enter saves, esc cancels
	// (#332).
	records  bool
	saving   bool
	savePath string

	// The permutation pass (#274). permute says one follows the main pass;
	// main is the main pass's last event once it has finished, and perm the
	// pass itself once there are seeds for it.
	permute bool
	main    *scan.Event
	perm    *permutationPass

	eta     *output.ETA // time-left estimator, as on the CLI progress line (#191)
	etaText string      // "" until the estimate has warmed up
}

func newScanViewModel(width, height int, simMode bool) scanViewModel {
	vp := viewport.New(viewport.WithWidth(max(1, width)), viewport.WithHeight(1))
	vp.Style = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("238"))

	prog := progress.New(
		progress.WithDefaultBlend(),
		progress.WithWidth(max(1, width-4)),
	)

	m := scanViewModel{
		viewport: vp,
		progress: prog,
		width:    width,
		height:   height,
		simMode:  simMode,
	}
	m.layout()
	return m
}

// layout sizes the viewport from the terminal size minus the fixed chrome and
// the notices currently shown, never going below one row (#37, #43).
func (m *scanViewModel) layout() {
	m.viewport.SetWidth(max(1, m.width))
	msgLines := 0
	if mv := m.messagesView(); mv != "" {
		msgLines = lipgloss.Height(mv)
	}
	if m.done {
		// chromeLines has one line for the counters; a narrow terminal
		// needs more (#343).
		msgLines += lipgloss.Height(m.countersLine()) - 1
	}
	m.viewport.SetHeight(max(1, m.height-chromeLines-msgLines))
	m.progress.SetWidth(max(1, m.width-4))
}

// messagesView renders at most maxShownMessages notices, newest last.
func (m scanViewModel) messagesView() string {
	if len(m.messages) == 0 {
		return ""
	}
	shown := m.messages
	var lines []string
	if len(shown) > maxShownMessages {
		lines = append(lines, dimStyle.Render(fmt.Sprintf("  +%d earlier notices", len(shown)-maxShownMessages)))
		shown = shown[len(shown)-maxShownMessages:]
	}
	return strings.Join(append(lines, shown...), "\n")
}

// addMessage records a notice and re-sizes the viewport to make room for it.
func (m *scanViewModel) addMessage(msg string) {
	m.messages = append(m.messages, msg)
	m.layout()
}

// filtered reports whether a filter is narrowing the results.
func (m *scanViewModel) filtered() bool { return m.filter != "" || m.takeoverOnly }

// refresh pushes buffered results into the viewport if they changed. While a
// filter is on, only matching results are shown and the view stays where the
// user scrolled it instead of following new results.
func (m *scanViewModel) refresh() {
	if !m.dirty {
		return
	}
	lines := make([]string, 0, len(m.results))
	shown := 0
	for _, r := range m.results {
		if !m.matches(r) {
			continue
		}
		shown++
		lines = append(lines, r.line)
		if m.records {
			lines = append(lines, dimStyle.Render("    "+recordsText(r.res)))
		}
	}
	m.shown = shown
	content := strings.Join(lines, "\n")
	if m.dropped > 0 {
		content = dimStyle.Render(fmt.Sprintf("(%d earlier results not shown)", m.dropped)) + "\n" + content
	}
	m.viewport.SetContent(content)
	if !m.filtered() {
		m.viewport.GotoBottom()
	}
	m.dirty = false
}

// matches reports whether the filter lets r through.
func (m *scanViewModel) matches(r resultLine) bool {
	return (!m.takeoverOnly || r.takeover) && strings.Contains(r.name, strings.ToLower(m.filter))
}

// recordsText renders a result's records as "A=192.0.2.1 CNAME=x.example.net",
// as -show-records does, or says it has none.
func recordsText(r output.Result) string {
	parts := make([]string, 0, len(r.Records))
	for _, rec := range r.Records {
		parts = append(parts, rec.Type+"="+rec.Value)
	}
	if len(parts) == 0 {
		return "(no records)"
	}
	return strings.Join(parts, " ")
}

// handleFilterKey applies a key to the result filter, or v to the records
// view, and reports whether it used it. While typing, every key but ctrl+c
// edits the filter.
func (m *scanViewModel) handleFilterKey(msg tea.KeyPressMsg) bool {
	if m.typing {
		switch {
		case msg.Code == tea.KeyEnter:
			m.typing = false
		case msg.Code == tea.KeyEscape:
			m.typing, m.filter = false, ""
		case msg.Code == tea.KeyBackspace:
			if r := []rune(m.filter); len(r) > 0 {
				m.filter = string(r[:len(r)-1])
			}
		case msg.Text != "":
			m.filter += strings.ToLower(msg.Text)
		default:
			return msg.String() != "ctrl+c"
		}
		m.dirty = true
		m.refresh()
		return true
	}
	switch msg.String() {
	case "/":
		m.typing = true
	case "t":
		m.takeoverOnly = !m.takeoverOnly
	case "v":
		m.records = !m.records
	case "esc":
		if !m.filtered() {
			return false
		}
		m.filter, m.takeoverOnly = "", false
	default:
		return false
	}
	m.dirty = true
	m.refresh()
	return true
}

// hint renders the key hint line cut to the terminal width, so a long
// filter cannot wrap it and push the layout past chromeLines.
func (m scanViewModel) hint(s string) string {
	return hintStyle.MaxWidth(max(1, m.width)).Render(s)
}

// filterHint is the key hint line's filter part.
func (m scanViewModel) filterHint() string {
	switch {
	case m.typing:
		return "filter: " + m.filter + "█  (enter keep  •  esc clear)"
	case m.filtered():
		desc := []string{}
		if m.filter != "" {
			desc = append(desc, fmt.Sprintf("%q", m.filter))
		}
		if m.takeoverOnly {
			desc = append(desc, "takeovers")
		}
		return fmt.Sprintf("showing %d of %d (%s)  •  esc clear", m.shown, len(m.results), strings.Join(desc, ", "))
	}
	return "/ filter  •  t takeovers  •  v records"
}

// doneHint is the finished screen's key hint line, or the save prompt while
// it is open (#332).
func (m scanViewModel) doneHint() string {
	if m.saving {
		return m.hint("  save to: " + m.savePath + "█  (enter save  •  esc cancel)")
	}
	return m.hint("  r new scan  •  s save  •  q quit  •  " + m.filterHint())
}

// handleSaveKey edits the save prompt's path. It reports whether the user
// pressed enter to save; esc closes the prompt.
func (m *scanViewModel) handleSaveKey(msg tea.KeyPressMsg) (save bool) {
	switch {
	case msg.Code == tea.KeyEnter:
		m.saving = false
		return strings.TrimSpace(m.savePath) != ""
	case msg.Code == tea.KeyEscape:
		m.saving = false
	case msg.Code == tea.KeyBackspace:
		if r := []rune(m.savePath); len(r) > 0 {
			m.savePath = string(r[:len(r)-1])
		}
	case msg.Text != "":
		m.savePath += msg.Text
	}
	return false
}

// toSave returns the results a save writes: those the filter shows.
func (m *scanViewModel) toSave() []output.Result {
	out := make([]output.Result, 0, len(m.results))
	for _, r := range m.results {
		if m.matches(r) {
			out = append(out, r.res)
		}
	}
	return out
}

func (m scanViewModel) Update(msg tea.Msg) (scanViewModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.layout()
		m.refresh()

	case eventMsg:
		m.applyEvent(msg.Event)
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

// applyEvent updates the view for one engine event. Kinds it does not know
// are ignored.
func (m *scanViewModel) applyEvent(ev scan.Event) {
	switch ev.Kind {
	case scan.EventResult:
		prefix := "Found: "
		if m.simMode {
			prefix = "Found (sim): "
		}
		line := resultStyle.Render(prefix + ev.Result.Subdomain)
		if ev.Result.Takeover != "" {
			line += wildcardStyle.Render("  ⚠ takeover? " + ev.Result.Takeover)
		}
		if ev.Result.Internal != "" {
			line += wildcardStyle.Render("  internal: " + ev.Result.Internal)
		}
		if m.perm != nil {
			m.perm.found++
			line += dimStyle.Render("  permutation")
		}
		// Model.record fills in what proposed the result.
		res := output.Result{Result: ev.Result, Permutation: m.perm != nil}
		m.results = append(m.results, resultLine{name: strings.ToLower(ev.Result.Subdomain), takeover: ev.Result.Takeover != "", line: line, res: res})
		if len(m.results) > maxResultLines {
			// Evict in chunks so the copy cost is amortized across results.
			n := len(m.results) - maxResultLines + maxResultLines/10
			m.dropped += n
			m.results = append([]resultLine(nil), m.results[n:]...)
		}
		m.dirty = true
		if len(m.results)+m.dropped <= liveRefreshLimit {
			m.refresh()
		}

	case scan.EventProgress:
		m.processed = ev.Processed
		m.total = ev.Total
		m.found = ev.Found
		if m.main != nil {
			m.found += m.main.Found // the bar is the pass's, the count the scan's
		}
		m.etaText = ""
		if m.eta == nil {
			m.eta = &output.ETA{}
		}
		if left, ok := m.eta.Update(ev.Processed, ev.Total); ok {
			m.etaText = output.FormatETA(left)
		}
		m.refresh()

	case scan.EventNotice:
		m.addMessage(wildcardStyle.Render("⚠ " + scan.Render(ev.Message, settingLabel)))

	case scan.EventError:
		text := scan.Render(ev.Message, settingLabel)
		if !ev.Fatal {
			// The reliability warning under No Abort: the scan goes on, so
			// it is a warning, not the scan's error (#308).
			m.addMessage(wildcardStyle.Render("⚠ " + text))
			break
		}
		m.addMessage(errorStyle.Render("✗ " + text))
		if m.errText == "" {
			m.errText = text
		}

	case scan.EventDone:
		m.scanFailed = m.scanFailed || ev.Failed
		switch {
		case m.main != nil:
			// The permutation pass ended. The counters are both passes'; one
			// that stopped before its candidates leaves the main pass's.
			m.done = true
			m.processed, m.total, m.found = m.main.Processed, m.main.Total, m.main.Found
			if p := m.perm; p != nil && !ev.Stopped {
				p.done, p.final = true, ev
				m.processed += ev.Processed
				m.total += ev.Total
				m.found += ev.Found
				m.stats = addStats(m.main.Stats, ev.Stats)
			}
		case ev.Stopped:
			m.done, m.stopped = true, true
		default:
			m.processed = ev.Processed
			m.total = ev.Total
			m.found = ev.Found
			m.stats = ev.Stats
			// With Permute on, a finished main pass is followed by the
			// permutation pass, unless the user or the reliability guard
			// stopped the scan, as on the command line.
			if m.permute && !m.aborted && !ev.Failed {
				m.main = &ev
			} else {
				m.done = true
			}
		}
		m.layout() // the finished counters may take more than one line
		m.refresh()
	}
}

func (m scanViewModel) View() string {
	var b strings.Builder

	// Header
	mode := "LIVE"
	if m.simMode {
		mode = fmt.Sprintf("SIMULATION, seed %d", m.seed)
	}
	b.WriteString(logo() + "\n")
	stage := ""
	if m.main != nil && !m.done {
		stage = " - permutation pass"
	}
	b.WriteString(headerStyle.Render(fmt.Sprintf("Scanning [%s mode]%s", mode, stage)) + "\n\n")

	// Extra messages (wildcard, errors), capped so the layout cannot overflow.
	if mv := m.messagesView(); mv != "" {
		b.WriteString(mv + "\n")
	}

	// Viewport
	b.WriteString(m.viewport.View() + "\n")

	// Progress bar
	pct := 0.0
	if m.total > 0 {
		pct = float64(m.processed) / float64(m.total)
	}
	b.WriteString(m.progress.ViewAs(pct) + "\n")

	// Status line
	switch {
	case m.failed():
		b.WriteString(errorStyle.Render("Failed: "+m.errText) + "\n")
		b.WriteString(m.countersLine() + "\n")
		b.WriteString(m.doneHint())
	case m.done && (m.aborted || m.stopped):
		if !m.stopped {
			b.WriteString(m.verdictLine() + "\n")
		}
		b.WriteString(m.countersLine() + "\n")
		b.WriteString(m.doneHint())
	case m.done:
		b.WriteString(m.verdictLine() + "\n")
		b.WriteString(m.countersLine() + "\n")
		b.WriteString(m.doneHint())
	default:
		status := fmt.Sprintf("  %d/%d processed  •  %d found", m.processed, m.total, m.found)
		if m.etaText != "" {
			status += "  •  ETA " + m.etaText
		}
		b.WriteString(dimStyle.Render(status) + "\n")
		b.WriteString(m.hint("  ctrl+c to abort  •  " + m.filterHint()))
	}

	return b.String()
}

// verdictLine renders the run-quality verdict and its reason, the ones the
// output file's summary carries, colored by rank and cut to the terminal
// width so it stays one line (#312).
func (m scanViewModel) verdictLine() string {
	status := report.StatusOK
	if m.aborted {
		status = report.StatusInterrupted
	}
	stats := m.stats
	if m.main != nil {
		stats = m.main.Stats // m.stats may count the permutation pass too
	}
	t := report.Target("", status, "", true, scan.Event{Stats: stats}, settingLabel)
	m.perm.summarize(&t, m.aborted, m.errText)
	style := resultStyle
	switch scan.VerdictRank(t.Verdict) {
	case 1:
		style = wildcardStyle
	case 2:
		style = errorStyle
	}
	return style.Bold(true).MaxWidth(max(1, m.width)).Render("Verdict: " + t.Verdict + " - " + t.Reason)
}

// countersLine renders the finished screen's counters, wrapped to the
// terminal width: with every counter set it is longer than 80 columns, and
// a line the terminal wraps by itself would push the layout one row past
// what layout reserved for it (#343). layout counts the wrapped lines.
func (m scanViewModel) countersLine() string {
	text := fmt.Sprintf("processed %d/%d - found %d - nxdomain %d - timeout %d - refused %d - other %d - wildcard-filtered %d",
		m.processed, m.total, m.found, m.stats.NXDomain, m.stats.Timeout, m.stats.Refused, m.stats.Other, m.stats.WildcardFiltered)
	style := summaryStyle
	switch {
	case m.failed():
		style = dimStyle
	case m.aborted || m.stopped:
		text, style = "Aborted - "+text+m.extraCounts(), dimStyle
	default:
		text = "Done - " + text + m.extraCounts()
	}
	return style.Render(wrapCounters(text, max(1, m.width)))
}

// wrapCounters wraps a " - "-separated counters line to width, breaking only
// between counters so none is split; a counter wider than width is cut by
// lipgloss.Wrap.
func wrapCounters(text string, width int) string {
	var lines []string
	cur := ""
	for part := range strings.SplitSeq(text, " - ") {
		switch {
		case cur == "":
			cur = part
		case len(cur)+len(" - ")+len(part) <= width:
			cur += " - " + part
		default:
			lines = append(lines, cur)
			cur = part
		}
	}
	return lipgloss.Wrap(strings.Join(append(lines, cur), "\n"), width, "")
}

// extraCounts is the tail of the finished counters line: the run facts
// that are only worth showing when they are not zero.
func (m scanViewModel) extraCounts() string {
	var s string
	if m.stats.Skipped > 0 {
		s += fmt.Sprintf(" - skipped %d", m.stats.Skipped)
	}
	if m.stats.Retried > 0 {
		s += fmt.Sprintf(" - retried %d (recovered %d)", m.stats.Retried, m.stats.Recovered)
	}
	if m.stats.Takeover > 0 {
		s += fmt.Sprintf(" - takeover %d", m.stats.Takeover)
	}
	if m.stats.RateBackoffs > 0 {
		s += fmt.Sprintf(" - rate back-offs %d", m.stats.RateBackoffs)
	}
	return s
}

// failed reports whether the finished scan failed, mirroring the CLI exit
// code. The engine says so on each pass's EventDone (#308): a fatal error
// (preflight failure, wildcard abort, reliability abort) fails the scan, the
// reliability warning under -no-abort does not, and neither does a user
// abort (#55), even during a permutation pass that follows that warning
// (#343).
func (m scanViewModel) failed() bool {
	return m.done && m.scanFailed
}

type wordlistLoadedMsg struct {
	cfg     formValues
	entries []string
	skipped int
	err     error
	pool    *dns.Pool // built from the Resolver Pool file, if one is set (#195)
	poolErr error     // the pool file could not be read or parsed
	// The passive sources' answers, already merged into entries, and the
	// candidate set that knows who proposed each name (#274, #347).
	lookups []sourceLookup
	cands   *candidates.Set
}
