package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/validate"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// Field order - Simulate is now field 2 so it's reachable in 2 tabs.
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
	fieldTypes       = 8
	fieldRecursive   = 9
	fieldDepth       = 10 // only active when recursive=ON
	fieldRate        = 11
	fieldMaxQueries  = 12
	fieldOutput      = 13
	fieldFormat      = 14
	fieldForce       = 15
	fieldNoAbort     = 16
	fieldCount       = 17
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
	7,  // fieldTypes       → inputs[7]
	-1, // fieldRecursive   → toggle
	8,  // fieldDepth       → inputs[8]
	9,  // fieldRate        → inputs[9]
	12, // fieldMaxQueries  → inputs[12]
	10, // fieldOutput      → inputs[10]
	11, // fieldFormat      → inputs[11]
	-1, // fieldForce       → toggle
	-1, // fieldNoAbort     → toggle
}

// formModel is the configuration form screen.
type formModel struct {
	inputs  []textinput.Model
	toggles [4]bool // [simulate, force, recursive, noAbort]
	focus   int
	err     string
	loading bool // wordlist is loading in the background; ctrl+r is ignored
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

	// inputs[0..7] correspond to the non-toggle fields.
	m.inputs = []textinput.Model{
		newInput("e.g. example.com", str(saved.Domain, "")),                                                // 0 Domain
		newInput("e.g. examples/sample_wordlist.txt", str(saved.Wordlist, "examples/sample_wordlist.txt")), // 1 Wordlist
		newInput("1–100", intStr(saved.HitRate, "15")),                                                     // 2 HitRate
		newInput("e.g. 8.8.8.8:53", str(saved.DNSServer, validate.DefaultDNSServer)),                       // 3 DNSServer
		newInput("e.g. 100", intStr(saved.Concurrency, "100")),                                             // 4 Concurrency
		newInput("e.g. 1000", intStr(saved.TimeoutMs, "1000")),                                             // 5 Timeout
		newInput("e.g. 1", intStr(saved.Attempts, "1")),                                                    // 6 Attempts
		newInput("e.g. A,AAAA,CNAME", str(saved.Types, "A,AAAA")),                                          // 7 Types
		newInput("e.g. 2", intStr(saved.Depth, "1")),                                                       // 8 Depth
		newInput("0 = unlimited", intStr(saved.Rate, "0")),                                                 // 9 Rate
		newInput("optional, e.g. results.txt", str(saved.Output, "")),                                      // 10 Output file
		newInput("text, json, jsonl, csv", str(saved.Format, "text")),                                      // 11 Format
		newInput("0 = unlimited", intStr(saved.MaxQueries, "0")),                                           // 12 Max queries
	}

	m.toggles[0] = saved.Simulate
	m.toggles[1] = saved.Force
	m.toggles[2] = saved.Recursive
	m.toggles[3] = saved.NoAbort

	// Focus domain on start - cursor blink cmd returned from Init.
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
	return m.focus == fieldSimulate || m.focus == fieldForce || m.focus == fieldRecursive || m.focus == fieldNoAbort
}

func (m *formModel) toggleArrayIndex() int {
	switch m.focus {
	case fieldSimulate:
		return 0
	case fieldForce:
		return 1
	case fieldNoAbort:
		return 3
	default: // fieldRecursive
		return 2
	}
}

// moveFocus advances focus by delta (+1 or -1), skipping gated fields: HitRate
// when simulate is OFF and Depth when recursive is OFF.
func (m *formModel) moveFocus(delta int) {
	for {
		m.focus = (m.focus + delta + fieldCount) % fieldCount
		if m.focus == fieldHitRate && !m.toggles[0] {
			continue
		}
		if m.focus == fieldDepth && !m.toggles[2] {
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

	// Hit Rate - only shown when simulate is ON.
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

	// Record types
	row(fieldTypes, "Record Types", m.inputs[7].View())

	// Recursive toggle
	recurseVal := toggleVal(m.toggles[2])
	recurseHint := ""
	if m.focus == fieldRecursive {
		recurseHint = blurredStyle.Render("  [space to toggle]")
	}
	row(fieldRecursive, "Recursive", recurseVal+recurseHint)

	// Depth - only shown when recursive is ON.
	if m.toggles[2] {
		row(fieldDepth, "Depth", m.inputs[8].View())
	} else {
		b.WriteString(dimmedRow.Render("  Depth:              (enable Recursive)") + "\n")
	}

	// Rate and query cap
	row(fieldRate, "Rate (qps)", m.inputs[9].View())
	row(fieldMaxQueries, "Max Names", m.inputs[12].View())

	// Output file (optional) and its format
	row(fieldOutput, "Output File", m.inputs[10].View())
	row(fieldFormat, "Format", m.inputs[11].View())

	// Force toggle
	forceVal := toggleVal(m.toggles[1])
	forceHint := ""
	if m.focus == fieldForce {
		forceHint = blurredStyle.Render("  [space to toggle]")
	}
	row(fieldForce, "Force", forceVal+forceHint)

	// No-abort toggle: keep scanning past the reliability guard.
	noAbortHint := ""
	if m.focus == fieldNoAbort {
		noAbortHint = blurredStyle.Render("  [space to toggle]")
	}
	row(fieldNoAbort, "No Abort", toggleVal(m.toggles[3])+noAbortHint)

	if m.err != "" {
		b.WriteString("\n" + errorStyle.Render("  ✗ "+m.err) + "\n")
	}
	if m.loading {
		b.WriteString("\n" + dimStyle.Render("  Loading wordlist...") + "\n")
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

// expandHome expands a leading "~/" (or a bare "~"). The form has no shell to
// do it, so without this "~/lists/words.txt" fails as a relative path.
func expandHome(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") && !strings.HasPrefix(path, `~\`) {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[1:])
}

// validate checks all inputs and returns a scan config or an error string.
func (m *formModel) validate() (formValues, string) {
	rawDomain := strings.TrimSpace(m.inputs[0].Value())
	if rawDomain == "" {
		return formValues{}, "Domain is required"
	}
	// Same normalization as the CLI, so a pasted URL or Example.COM. scans
	// (and saves) the same canonical domain (#54).
	domain, _, err := validate.NormalizeDomain(rawDomain)
	if err != nil {
		return formValues{}, err.Error()
	}
	wl := expandHome(strings.TrimSpace(m.inputs[1].Value()))
	if wl == "" {
		return formValues{}, "Wordlist path is required"
	}
	// The TUI owns stdin, so reading a wordlist from it would block forever (#55).
	if wl == wordlist.Stdin {
		return formValues{}, "Wordlist from standard input (-) is not supported in the TUI; enter a file path"
	}
	dnsServer := strings.TrimSpace(m.inputs[3].Value())
	if dnsServer == "" {
		dnsServer = validate.DefaultDNSServer
	}

	// The form only parses its text fields here; ranges and the resolver are
	// checked by scan.Options.Validate, the same validator the CLI uses (#80).
	num := func(field int, name string, blank int) int {
		s := strings.TrimSpace(m.inputs[field].Value())
		if err != nil || s == "" {
			return blank
		}
		n, perr := strconv.Atoi(s)
		if perr != nil {
			err = fmt.Errorf("%s must be a whole number, got %q", name, m.inputs[field].Value())
		}
		return n
	}
	concurrency := num(4, "Concurrency", 0)
	timeout := num(5, "Timeout", 0)
	attempts := num(6, "Attempts", 0)
	// Hit rate only matters in simulation mode, and depth only when
	// recursive is on; otherwise their fields must not block the scan.
	hitRate := 15
	if m.toggles[0] {
		hitRate = num(2, "Hit rate", 0)
	}
	depth := 1
	if m.toggles[2] {
		depth = num(8, "Depth", 1)
	}
	rate := num(9, "Rate", 0)               // blank means unlimited
	maxQueries := num(12, "Max queries", 0) // blank means unlimited
	if err != nil {
		return formValues{}, err.Error()
	}

	recordTypes, err := dns.ParseTypes(m.inputs[7].Value())
	if err != nil {
		return formValues{}, err.Error()
	}

	// Output file is optional; the format applies only to that file and is
	// validated even when no file is set so a typo is caught early.
	outputFile := expandHome(strings.TrimSpace(m.inputs[10].Value()))
	formatStr := strings.TrimSpace(m.inputs[11].Value())
	if formatStr == "" {
		formatStr = "text"
	}
	format, err := output.ParseFormat(formatStr)
	if err != nil {
		return formValues{}, err.Error()
	}

	v := formValues{
		domain:      domain,
		wordlist:    wl,
		dnsServer:   dnsServer,
		concurrency: concurrency,
		timeoutMs:   timeout,
		attempts:    attempts,
		hitRate:     hitRate,
		recordTypes: recordTypes,
		recursive:   m.toggles[2],
		depth:       depth,
		rate:        rate,
		maxQueries:  maxQueries,
		noAbort:     m.toggles[3],
		outputFile:  outputFile,
		format:      format,
		formatName:  formatStr,
		simulate:    m.toggles[0],
		force:       m.toggles[1],
	}
	if err := v.options(nil, 0).Validate(); err != nil {
		return formValues{}, err.Error()
	}
	return v, ""
}

// options maps the form onto the scan options the CLI also builds, so both
// front ends share one validator and one Config builder (#80).
func (v formValues) options(entries []string, seed uint64) scan.Options {
	return scan.Options{
		Domain:      v.domain,
		Entries:     entries,
		Concurrency: v.concurrency,
		TimeoutMs:   v.timeoutMs,
		DNSServer:   v.dnsServer,
		Simulate:    v.simulate,
		HitRate:     v.hitRate,
		Seed:        seed,
		Attempts:    v.attempts,
		Force:       v.force,
		Types:       v.recordTypes,
		Recursive:   v.recursive,
		Depth:       v.depth,
		Rate:        v.rate,
		MaxQueries:  v.maxQueries,
		NoAbort:     v.noAbort,
	}
}

type formValues struct {
	domain      string
	wordlist    string
	dnsServer   string
	concurrency int
	timeoutMs   int
	attempts    int
	hitRate     int
	recordTypes []string
	recursive   bool
	depth       int
	rate        int
	maxQueries  int
	noAbort     bool
	outputFile  string
	format      output.Format
	formatName  string
	simulate    bool
	force       bool
}
