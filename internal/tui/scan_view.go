package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

var (
	resultStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	headerStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	summaryStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220")).MarginTop(1)
	wildcardStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
)

const (
	// chromeLines is the fixed layout around the viewport: logo (2), header
	// and blank line (2), progress bar (1), the done-state summary with its
	// top margin (2), and the key hint with its top margin (2).
	chromeLines = 9
	// maxShownMessages caps the notices rendered above the viewport; older
	// ones collapse into a "+N earlier" line so the layout cannot overflow.
	maxShownMessages = 3
	// maxResultLines bounds the viewport buffer. The full result set still
	// goes to the output file when one is configured.
	maxResultLines = 10000
	// liveRefreshLimit is how many results are re-rendered on every event;
	// past it, content refreshes on progress ticks and at the end, so render
	// cost per result stays constant on large scans.
	liveRefreshLimit = 200
)

// resultLine is one result in the viewport buffer: its rendered line, and
// what the filter matches on (#221).
type resultLine struct {
	name     string
	takeover bool
	line     string
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
	noAbort      bool   // -no-abort: an error with a finished scan is only a warning
	outputErr    bool   // the results file could not be written in full (#155)
	width        int
	height       int
	simMode      bool
	seed         uint64 // simulation seed, shown so a TUI run can be reproduced

	eta     *output.ETA // time-left estimator, as on the CLI progress line (#191)
	etaText string      // "" until the estimate has warmed up
}

func newScanViewModel(width, height int, simMode bool) scanViewModel {
	vp := viewport.New(max(1, width), 1)
	vp.Style = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("238"))

	prog := progress.New(
		progress.WithDefaultGradient(),
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
	m.viewport.Width = max(1, m.width)
	msgLines := 0
	if mv := m.messagesView(); mv != "" {
		msgLines = lipgloss.Height(mv)
	}
	m.viewport.Height = max(1, m.height-chromeLines-msgLines)
	m.progress.Width = max(1, m.width-4)
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
	needle := strings.ToLower(m.filter)
	for _, r := range m.results {
		if (m.takeoverOnly && !r.takeover) || !strings.Contains(r.name, needle) {
			continue
		}
		lines = append(lines, r.line)
	}
	m.shown = len(lines)
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

// handleFilterKey applies a key to the result filter and reports whether it
// used it. While typing, every key but ctrl+c edits the filter.
func (m *scanViewModel) handleFilterKey(msg tea.KeyMsg) bool {
	if m.typing {
		switch msg.Type {
		case tea.KeyEnter:
			m.typing = false
		case tea.KeyEsc:
			m.typing, m.filter = false, ""
		case tea.KeyBackspace:
			if r := []rune(m.filter); len(r) > 0 {
				m.filter = string(r[:len(r)-1])
			}
		case tea.KeyRunes, tea.KeySpace:
			m.filter += strings.ToLower(string(msg.Runes))
		default:
			return msg.Type != tea.KeyCtrlC
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
	return "/ filter  •  t takeovers"
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
		m.results = append(m.results, resultLine{name: strings.ToLower(ev.Result.Subdomain), takeover: ev.Result.Takeover != "", line: line})
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
		m.addMessage(errorStyle.Render("✗ " + text))
		if m.errText == "" {
			m.errText = text
		}

	case scan.EventDone:
		m.done = true
		if ev.Stopped {
			m.stopped = true
		} else {
			m.processed = ev.Processed
			m.total = ev.Total
			m.found = ev.Found
			m.stats = ev.Stats
		}
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
	b.WriteString(headerStyle.Render(fmt.Sprintf("Scanning [%s mode]", mode)) + "\n\n")

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
		b.WriteString(dimStyle.Render(fmt.Sprintf(
			"processed %d/%d - found %d - nxdomain %d - timeout %d - refused %d - other %d - wildcard-filtered %d",
			m.processed, m.total, m.found, m.stats.NXDomain, m.stats.Timeout, m.stats.Refused, m.stats.Other, m.stats.WildcardFiltered,
		)) + "\n")
		b.WriteString(m.hint("  r new scan  •  q quit  •  " + m.filterHint()))
	case m.done && (m.aborted || m.stopped):
		b.WriteString(dimStyle.Render(fmt.Sprintf(
			"Aborted - processed %d/%d - found %d - nxdomain %d - timeout %d - refused %d - other %d - wildcard-filtered %d",
			m.processed, m.total, m.found, m.stats.NXDomain, m.stats.Timeout, m.stats.Refused, m.stats.Other, m.stats.WildcardFiltered,
		)) + "\n")
		b.WriteString(m.hint("  r new scan  •  q quit  •  " + m.filterHint()))
	case m.done:
		b.WriteString(summaryStyle.Render(fmt.Sprintf(
			"Done - processed %d/%d - found %d - nxdomain %d - timeout %d - refused %d - other %d - wildcard-filtered %d",
			m.processed, m.total, m.found, m.stats.NXDomain, m.stats.Timeout, m.stats.Refused, m.stats.Other, m.stats.WildcardFiltered,
		)) + "\n")
		b.WriteString(m.hint("  r new scan  •  q quit  •  " + m.filterHint()))
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

// failed reports whether the finished scan failed, mirroring the CLI exit
// code: an error fails the scan unless it finished under -no-abort. A scan
// that ended without EventDone after an error (preflight failure, wildcard
// abort) is a failure, not a user abort (#55).
func (m scanViewModel) failed() bool {
	return m.done && m.errText != "" && (m.stopped || !m.noAbort)
}

type wordlistLoadedMsg struct {
	cfg     formValues
	entries []string
	skipped int
	err     error
	pool    *dns.Pool // built from the Resolver Pool file, if one is set (#195)
	poolErr error     // the pool file could not be read or parsed
}
