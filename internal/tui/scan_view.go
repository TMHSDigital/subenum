package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	resultStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	headerStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	summaryStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220")).MarginTop(1)
	wildcardStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
)

// scanViewModel is the live-results screen.
type scanViewModel struct {
	viewport    viewport.Model
	progress    progress.Model
	results     []string
	messages    []string // wildcard / error messages
	processed   int64
	total       int64
	found       int64
	done        bool
	aborted     bool
	width       int
	height      int
	simMode     bool
}

func newScanViewModel(width, height int, simMode bool) scanViewModel {
	vp := viewport.New(width, height-8)
	vp.Style = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("238"))

	prog := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(width-4),
	)

	return scanViewModel{
		viewport: vp,
		progress: prog,
		width:    width,
		height:   height,
		simMode:  simMode,
	}
}

func (m scanViewModel) Update(msg tea.Msg) (scanViewModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - 8
		m.progress.Width = msg.Width - 4

	case resultMsg:
		prefix := "Found: "
		if m.simMode {
			prefix = "Found (sim): "
		}
		m.results = append(m.results, resultStyle.Render(prefix+msg.domain))
		m.viewport.SetContent(strings.Join(m.results, "\n"))
		m.viewport.GotoBottom()

	case progressMsg:
		m.processed = msg.processed
		m.total = msg.total
		m.found = msg.found

	case wildcardMsg:
		m.messages = append(m.messages, wildcardStyle.Render("⚠ "+msg.text))

	case errorMsg:
		m.messages = append(m.messages, errorStyle.Render("✗ "+msg.text))

	case doneMsg:
		m.done = true
		m.processed = msg.processed
		m.total = msg.total
		m.found = msg.found

	case abortedMsg:
		m.aborted = true
		m.done = true
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
		mode = "SIMULATION"
	}
	b.WriteString(headerStyle.Render(fmt.Sprintf("subenum — Scanning [%s mode]", mode)) + "\n\n")

	// Extra messages (wildcard, errors)
	for _, msg := range m.messages {
		b.WriteString(msg + "\n")
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
	if m.done && m.aborted {
		b.WriteString(dimStyle.Render(fmt.Sprintf(
			"Aborted — processed %d/%d — found %d",
			m.processed, m.total, m.found,
		)) + "\n")
	} else if m.done {
		b.WriteString(summaryStyle.Render(fmt.Sprintf(
			"Done — processed %d/%d — found %d subdomain(s)",
			m.processed, m.total, m.found,
		)) + "\n")
		b.WriteString(hintStyle.Render("  r new scan  •  q quit"))
	} else {
		b.WriteString(dimStyle.Render(fmt.Sprintf(
			"  %d/%d processed  •  %d found",
			m.processed, m.total, m.found,
		)) + "\n")
		b.WriteString(hintStyle.Render("  ctrl+c to abort"))
	}

	return b.String()
}

// Event message types for Bubble Tea.
type resultMsg struct{ domain string }
type progressMsg struct{ processed, total, found int64 }
type wildcardMsg struct{ text string }
type errorMsg struct{ text string }
type doneMsg struct{ processed, total, found int64 }
type abortedMsg struct{}
type startScanMsg struct{ cfg formValues }
