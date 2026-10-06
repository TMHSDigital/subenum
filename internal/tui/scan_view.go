package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/TMHSDigital/subenum/internal/dns"
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

// scanViewModel is the live-results screen.
type scanViewModel struct {
	viewport  viewport.Model
	progress  progress.Model
	results   []string
	dropped   int      // results evicted from the viewport buffer
	dirty     bool     // results changed since the last SetContent
	messages  []string // wildcard / error messages
	processed int64
	total     int64
	found     int64
	stats     scan.Stats
	done      bool
	aborted   bool   // the user pressed ctrl+c
	stopped   bool   // the scan stopped before testing candidates (preflight, wildcard abort, #99)
	errText   string // first scan error; the reason shown for a failed scan
	noAbort   bool   // -no-abort: an error with a finished scan is only a warning
	width     int
	height    int
	simMode   bool
	seed      uint64 // simulation seed, shown so a TUI run can be reproduced
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

// refresh pushes buffered results into the viewport if they changed.
func (m *scanViewModel) refresh() {
	if !m.dirty {
		return
	}
	content := strings.Join(m.results, "\n")
	if m.dropped > 0 {
		content = dimStyle.Render(fmt.Sprintf("(%d earlier results not shown)", m.dropped)) + "\n" + content
	}
	m.viewport.SetContent(content)
	m.viewport.GotoBottom()
	m.dirty = false
}

func (m scanViewModel) Update(msg tea.Msg) (scanViewModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.layout()
		m.refresh()

	case resultMsg:
		prefix := "Found: "
		if m.simMode {
			prefix = "Found (sim): "
		}
		line := resultStyle.Render(prefix + msg.domain)
		if msg.takeover != "" {
			line += wildcardStyle.Render("  ⚠ takeover? " + msg.takeover)
		}
		m.results = append(m.results, line)
		if len(m.results) > maxResultLines {
			// Evict in chunks so the copy cost is amortized across results.
			n := len(m.results) - maxResultLines + maxResultLines/10
			m.dropped += n
			m.results = append([]string(nil), m.results[n:]...)
		}
		m.dirty = true
		if len(m.results)+m.dropped <= liveRefreshLimit {
			m.refresh()
		}

	case progressMsg:
		m.processed = msg.processed
		m.total = msg.total
		m.found = msg.found
		m.refresh()

	case wildcardMsg:
		m.addMessage(wildcardStyle.Render("⚠ " + msg.text))

	case errorMsg:
		m.addMessage(errorStyle.Render("✗ " + msg.text))
		if m.errText == "" {
			m.errText = msg.text
		}

	case doneMsg:
		m.done = true
		m.processed = msg.processed
		m.total = msg.total
		m.found = msg.found
		m.stats = msg.stats
		m.refresh()

	case stoppedMsg:
		m.stopped = true
		m.done = true
		m.refresh()
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
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
		b.WriteString(hintStyle.Render("  r new scan  •  q quit"))
	case m.done && (m.aborted || m.stopped):
		b.WriteString(dimStyle.Render(fmt.Sprintf(
			"Aborted - processed %d/%d - found %d - nxdomain %d - timeout %d - refused %d - other %d - wildcard-filtered %d",
			m.processed, m.total, m.found, m.stats.NXDomain, m.stats.Timeout, m.stats.Refused, m.stats.Other, m.stats.WildcardFiltered,
		)) + "\n")
		b.WriteString(hintStyle.Render("  r new scan  •  q quit"))
	case m.done:
		b.WriteString(summaryStyle.Render(fmt.Sprintf(
			"Done - processed %d/%d - found %d - nxdomain %d - timeout %d - refused %d - other %d - wildcard-filtered %d",
			m.processed, m.total, m.found, m.stats.NXDomain, m.stats.Timeout, m.stats.Refused, m.stats.Other, m.stats.WildcardFiltered,
		)) + "\n")
		b.WriteString(hintStyle.Render("  r new scan  •  q quit"))
	default:
		b.WriteString(dimStyle.Render(fmt.Sprintf(
			"  %d/%d processed  •  %d found",
			m.processed, m.total, m.found,
		)) + "\n")
		b.WriteString(hintStyle.Render("  ctrl+c to abort"))
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

// Event message types for Bubble Tea.
type resultMsg struct {
	domain   string
	records  []dns.Record
	takeover string // DNS-only takeover hint (#71)
}
type progressMsg struct{ processed, total, found int64 }
type wildcardMsg struct{ text string }
type errorMsg struct{ text string }
type doneMsg struct {
	processed, total, found int64
	stats                   scan.Stats
}
type stoppedMsg struct{}
type wordlistLoadedMsg struct {
	cfg     formValues
	entries []string
	skipped int
	err     error
}
