package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Field order — Simulate is now field 2 so it's reachable in 2 tabs.
// Hit Rate only shows when Simulate is ON, so fieldCount varies; we handle
// that in navigation by skipping fieldHitRate when simulate is off.
const (
	fieldDomain      = 0
	fieldWordlist    = 1
	fieldSimulate    = 2 // promoted from 7
	fieldHitRate     = 3 // only active when simulate=ON
	fieldDNSServer   = 4
	fieldConcurrency = 5
	fieldTimeout     = 6
	fieldAttempts    = 7
	fieldForce       = 8
	fieldCount       = 9
)

var (
	focusedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))
	blurredStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	labelStyle    = lipgloss.NewStyle().Width(18)
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).MarginBottom(1)
	errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	hintStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).MarginTop(1)
	toggleOnStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Bold(true)
	dimmedRow     = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
)

// inputIndex maps field index → inputs slice index (skips toggle-only fields).
// Fields 2 (Simulate) and 8 (Force) are toggles, not text inputs.
// Field 3 (HitRate) is a text input but only rendered when simulate=ON.
var inputForField = [fieldCount]int{
	0,  // fieldDomain      → inputs[0]
	1,  // fieldWordlist    → inputs[1]
	-1, // fieldSimulate    → toggle
	2,  // fieldHitRate     → inputs[2]
	3,  // fieldDNSServer   → inputs[3]
	4,  // fieldConcurrency → inputs[4]
	5,  // fieldTimeout     → inputs[5]
	6,  // fieldAttempts    → inputs[6]
	-1, // fieldForce       → toggle
}

// formModel is the configuration form screen.
type formModel struct {
	inputs  []textinput.Model
	toggles [2]bool // [simulate, force]
	focus   int
	err     string
	width   int
}

// newFormModel creates a form, optionally pre-seeded from a saved config.
// Pass a zero-value savedConfig (and ok=false) to use hardcoded defaults.
func newFormModel(saved savedConfig) formModel {
	m := formModel{}

	str := func(saved, def string) string {
		if saved != "" {
			return saved
		}
		return def
	}
	intStr := func(saved int, def string) string {
		if saved > 0 {
			return fmt.Sprintf("%d", saved)
		}
		return def
	}

	newInput := func(placeholder, value string) textinput.Model {
		ti := textinput.New()
		ti.Placeholder = placeholder
		ti.SetValue(value)
		ti.PromptStyle = blurredStyle
		ti.TextStyle = blurredStyle
		return ti
	}

	// inputs[0..6] correspond to the non-toggle fields.
	m.inputs = []textinput.Model{
		newInput("e.g. example.com", str(saved.Domain, "")),                                                // 0 Domain
		newInput("e.g. examples/sample_wordlist.txt", str(saved.Wordlist, "examples/sample_wordlist.txt")), // 1 Wordlist
		newInput("1–100", intStr(saved.HitRate, "15")),                                                     // 2 HitRate
		newInput("e.g. 8.8.8.8:53", str(saved.DNSServer, "8.8.8.8:53")),                                    // 3 DNSServer
		newInput("e.g. 100", intStr(saved.Concurrency, "100")),                                             // 4 Concurrency
		newInput("e.g. 1000", intStr(saved.TimeoutMs, "1000")),                                             // 5 Timeout
		newInput("e.g. 1", intStr(saved.Attempts, "1")),                                                    // 6 Attempts
	}

	m.toggles[0] = saved.Simulate
	m.toggles[1] = saved.Force

	// Focus domain on start — cursor blink cmd returned from Init.
	m.inputs[0].Focus()
	m.inputs[0].PromptStyle = focusedStyle
	m.inputs[0].TextStyle = focusedStyle

	return m
}

// initCmd returns the blink command for the initially focused input.
func (m formModel) initCmd() tea.Cmd {
	return textinput.Blink
}

func (m *formModel) isToggle() bool {
	return m.focus == fieldSimulate || m.focus == fieldForce
}

func (m *formModel) toggleArrayIndex() int {
	if m.focus == fieldSimulate {
		return 0
	}
	return 1
}

// nextFocus advances focus by delta (+1 or -1), skipping HitRate when simulate is OFF.
func (m *formModel) moveFocus(delta int) {
	for {
		m.focus = (m.focus + delta + fieldCount) % fieldCount
		// Skip HitRate when simulate is OFF.
		if m.focus == fieldHitRate && !m.toggles[0] {
			continue
		}
		break
	}
}

func (m formModel) Update(msg tea.Msg) (formModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width

	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			// Blur current text input if any.
			if idx := inputForField[m.focus]; idx >= 0 {
				m.inputs[idx].Blur()
				m.inputs[idx].PromptStyle = blurredStyle
				m.inputs[idx].TextStyle = blurredStyle
			}
			m.moveFocus(+1)
			if idx := inputForField[m.focus]; idx >= 0 {
				m.inputs[idx].Focus()
				m.inputs[idx].PromptStyle = focusedStyle
				m.inputs[idx].TextStyle = focusedStyle
				return m, textinput.Blink
			}
			return m, nil

		case "shift+tab", "up":
			if idx := inputForField[m.focus]; idx >= 0 {
				m.inputs[idx].Blur()
				m.inputs[idx].PromptStyle = blurredStyle
				m.inputs[idx].TextStyle = blurredStyle
			}
			m.moveFocus(-1)
			if idx := inputForField[m.focus]; idx >= 0 {
				m.inputs[idx].Focus()
				m.inputs[idx].PromptStyle = focusedStyle
				m.inputs[idx].TextStyle = focusedStyle
				return m, textinput.Blink
			}
			return m, nil

		case " ":
			if m.isToggle() {
				m.toggles[m.toggleArrayIndex()] = !m.toggles[m.toggleArrayIndex()]
			}
		}
	}

	// Forward events to the focused text input.
	if idx := inputForField[m.focus]; idx >= 0 {
		var cmd tea.Cmd
		m.inputs[idx], cmd = m.inputs[idx].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m formModel) View() string {
	var b strings.Builder

	b.WriteString(logo() + "\n\n")
	b.WriteString(titleStyle.Render("Configure Scan") + "\n")

	row := func(fieldIdx int, label string, content string) {
		lbl := labelStyle.Render(label + ":")
		if m.focus == fieldIdx {
			b.WriteString(focusedStyle.Render("▸ ") + lbl + content + "\n")
		} else {
			b.WriteString("  " + lbl + content + "\n")
		}
	}

	// Domain
	row(fieldDomain, "Domain*", m.inputs[0].View())

	// Wordlist
	row(fieldWordlist, "Wordlist*", m.inputs[1].View())

	// Simulate toggle
	simVal := toggleVal(m.toggles[0])
	hint := ""
	if m.focus == fieldSimulate {
		hint = blurredStyle.Render("  [space to toggle]")
	}
	row(fieldSimulate, "Simulate", simVal+hint)

	// Hit Rate — only shown when simulate is ON.
	if m.toggles[0] {
		row(fieldHitRate, "Hit Rate (%)", m.inputs[2].View())
	} else {
		b.WriteString(dimmedRow.Render("  Hit Rate (%):       (enable Simulate)") + "\n")
	}

	// DNS Server
	row(fieldDNSServer, "DNS Server", m.inputs[3].View())

	// Concurrency
	row(fieldConcurrency, "Concurrency", m.inputs[4].View())

	// Timeout
	row(fieldTimeout, "Timeout (ms)", m.inputs[5].View())

	// Attempts
	row(fieldAttempts, "Attempts", m.inputs[6].View())

	// Force toggle
	forceVal := toggleVal(m.toggles[1])
	forceHint := ""
	if m.focus == fieldForce {
		forceHint = blurredStyle.Render("  [space to toggle]")
	}
	row(fieldForce, "Force", forceVal+forceHint)

	if m.err != "" {
		b.WriteString("\n" + errorStyle.Render("  ✗ "+m.err) + "\n")
	}

	b.WriteString(hintStyle.Render("\n  tab/↑↓ navigate  •  space toggle  •  ctrl+r run  •  ctrl+c quit"))

	return b.String()
}

func toggleVal(on bool) string {
	if on {
		return toggleOnStyle.Render("ON ")
	}
	return blurredStyle.Render("OFF")
}

// validate checks all inputs and returns a scan config or an error string.
func (m *formModel) validate() (formValues, string) {
	domain := strings.TrimSpace(m.inputs[0].Value())
	if domain == "" {
		return formValues{}, "Domain is required"
	}
	wl := strings.TrimSpace(m.inputs[1].Value())
	if wl == "" {
		return formValues{}, "Wordlist path is required"
	}
	dnsServer := strings.TrimSpace(m.inputs[3].Value())
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53"
	}

	concurrency, err := strconv.Atoi(strings.TrimSpace(m.inputs[4].Value()))
	if err != nil || concurrency < 1 {
		return formValues{}, fmt.Sprintf("Concurrency must be a positive integer, got %q", m.inputs[4].Value())
	}
	timeout, err := strconv.Atoi(strings.TrimSpace(m.inputs[5].Value()))
	if err != nil || timeout < 1 {
		return formValues{}, fmt.Sprintf("Timeout must be a positive integer (ms), got %q", m.inputs[5].Value())
	}
	attempts, err := strconv.Atoi(strings.TrimSpace(m.inputs[6].Value()))
	if err != nil || attempts < 1 {
		return formValues{}, fmt.Sprintf("Attempts must be >= 1, got %q", m.inputs[6].Value())
	}
	hitRate, err := strconv.Atoi(strings.TrimSpace(m.inputs[2].Value()))
	if err != nil || hitRate < 1 || hitRate > 100 {
		return formValues{}, fmt.Sprintf("Hit rate must be 1–100, got %q", m.inputs[2].Value())
	}

	return formValues{
		domain:      domain,
		wordlist:    wl,
		dnsServer:   dnsServer,
		concurrency: concurrency,
		timeoutMs:   timeout,
		attempts:    attempts,
		hitRate:     hitRate,
		simulate:    m.toggles[0],
		force:       m.toggles[1],
	}, ""
}

type formValues struct {
	domain      string
	wordlist    string
	dnsServer   string
	concurrency int
	timeoutMs   int
	attempts    int
	hitRate     int
	simulate    bool
	force       bool
}
