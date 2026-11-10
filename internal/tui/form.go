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

// Form fields in tab order. Each constant is both the field's position on the
// form and its index into formFields, formModel.inputs and formModel.toggles.
const (
	fieldDomain = iota
	fieldWordlist
	fieldSimulate
	fieldHitRate // only reachable when Simulate is ON
	fieldDNSServer
	fieldConcurrency
	fieldTimeout
	fieldAttempts
	fieldTypes
	fieldRecursive
	fieldDepth // only reachable when Recursive is ON
	fieldRate
	fieldMaxQueries
	fieldExclude
	fieldOutput
	fieldFormat
	fieldForce
	fieldNoAbort
	fieldCount
)

// fieldKind says how a form field is edited.
type fieldKind int

const (
	textField   fieldKind = iota // a text input
	toggleField                  // an ON/OFF switch flipped with space
)

// formField describes one form row. The form is built, navigated, rendered and
// labelled from formFields, so adding a field is one constant and one entry
// (plus reading it in validate).
type formField struct {
	label       string                   // row label; also names setting in engine messages
	kind        fieldKind                // text input or toggle
	placeholder string                   // text fields: hint shown while empty
	value       func(savedConfig) string // text fields: initial value
	on          func(savedConfig) bool   // toggles: initial state
	// gate is the toggle that must be ON for this field to be shown and
	// reachable. Zero means always shown (fieldDomain is never a toggle).
	gate    int
	setting scan.Setting // engine setting this field sets, if any
}

// formFields is indexed by the field constants.
var formFields = [fieldCount]formField{
	fieldDomain: {label: "Domain*", kind: textField, placeholder: "e.g. example.com",
		value: func(c savedConfig) string { return orDefault(c.Domain, "") }},
	fieldWordlist: {label: "Wordlist*", kind: textField, placeholder: "e.g. examples/sample_wordlist.txt",
		value: func(c savedConfig) string { return orDefault(c.Wordlist, "examples/sample_wordlist.txt") }},
	fieldSimulate: {label: "Simulate", kind: toggleField,
		on: func(c savedConfig) bool { return c.Simulate }},
	fieldHitRate: {label: "Hit Rate (%)", kind: textField, placeholder: "1–100", gate: fieldSimulate, setting: scan.SettingHitRate,
		value: func(c savedConfig) string { return intOrDefault(c.HitRate, "15") }},
	fieldDNSServer: {label: "DNS Server", kind: textField, placeholder: "e.g. 8.8.8.8:53",
		value: func(c savedConfig) string { return orDefault(c.DNSServer, validate.DefaultDNSServer) }},
	fieldConcurrency: {label: "Concurrency", kind: textField, placeholder: "e.g. 100", setting: scan.SettingConcurrency,
		value: func(c savedConfig) string { return intOrDefault(c.Concurrency, "100") }},
	fieldTimeout: {label: "Timeout (ms)", kind: textField, placeholder: "e.g. 1000", setting: scan.SettingTimeout,
		value: func(c savedConfig) string { return intOrDefault(c.TimeoutMs, "1000") }},
	fieldAttempts: {label: "Attempts", kind: textField, placeholder: "e.g. 1", setting: scan.SettingAttempts,
		value: func(c savedConfig) string { return intOrDefault(c.Attempts, "1") }},
	fieldTypes: {label: "Record Types", kind: textField, placeholder: "e.g. A,AAAA,CNAME",
		value: func(c savedConfig) string { return orDefault(c.Types, "A,AAAA") }},
	fieldRecursive: {label: "Recursive", kind: toggleField, setting: scan.SettingRecursive,
		on: func(c savedConfig) bool { return c.Recursive }},
	fieldDepth: {label: "Depth", kind: textField, placeholder: "e.g. 2", gate: fieldRecursive, setting: scan.SettingDepth,
		value: func(c savedConfig) string { return intOrDefault(c.Depth, "1") }},
	fieldRate: {label: "Rate (qps)", kind: textField, placeholder: "0 = unlimited", setting: scan.SettingRate,
		value: func(c savedConfig) string { return intOrDefault(c.Rate, "0") }},
	fieldMaxQueries: {label: "Max Names", kind: textField, placeholder: "0 = unlimited", setting: scan.SettingMaxQueries,
		value: func(c savedConfig) string { return intOrDefault(c.MaxQueries, "0") }},
	fieldExclude: {label: "Exclude", kind: textField, placeholder: "optional, e.g. vpn.example.com,*.corp.example.com", setting: scan.SettingExclude,
		value: func(c savedConfig) string { return orDefault(c.Exclude, "") }},
	fieldOutput: {label: "Output File", kind: textField, placeholder: "optional, e.g. results.txt",
		value: func(c savedConfig) string { return orDefault(c.Output, "") }},
	fieldFormat: {label: "Format", kind: textField, placeholder: "text, json, jsonl, csv",
		value: func(c savedConfig) string { return orDefault(c.Format, "text") }},
	fieldForce: {label: "Force", kind: toggleField, setting: scan.SettingForce,
		on: func(c savedConfig) bool { return c.Force }},
	fieldNoAbort: {label: "No Abort", kind: toggleField,
		on: func(c savedConfig) bool { return c.NoAbort }},
}

// settingsWithoutField label the engine settings the form has no field for.
var settingsWithoutField = map[scan.Setting]string{
	scan.SettingMaxDuration: "Max Duration",
}

func orDefault(saved, def string) string {
	if saved != "" {
		return saved
	}
	return def
}

func intOrDefault(saved int, def string) string {
	if saved > 0 {
		return strconv.Itoa(saved)
	}
	return def
}

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

// formModel is the configuration form screen.
type formModel struct {
	inputs  [fieldCount]textinput.Model // used by text fields
	toggles [fieldCount]bool            // used by toggle fields
	focus   int
	err     string
	loading bool // wordlist is loading in the background; ctrl+r is ignored
	width   int
}

// newFormModel creates a form, optionally pre-seeded from a saved config.
// Pass a zero-value savedConfig (and ok=false) to use hardcoded defaults.
func newFormModel(saved savedConfig) formModel {
	m := formModel{}

	for f, spec := range formFields {
		switch spec.kind {
		case textField:
			ti := textinput.New()
			ti.Placeholder = spec.placeholder
			ti.SetValue(spec.value(saved))
			ti.PromptStyle = blurredStyle
			ti.TextStyle = blurredStyle
			m.inputs[f] = ti
		case toggleField:
			m.toggles[f] = spec.on(saved)
		}
	}

	// Focus domain on start - cursor blink cmd returned from Init.
	m.inputs[fieldDomain].Focus()
	m.inputs[fieldDomain].PromptStyle = focusedStyle
	m.inputs[fieldDomain].TextStyle = focusedStyle

	return m
}

// initCmd returns the blink command for the initially focused input.
func (m formModel) initCmd() tea.Cmd {
	return textinput.Blink
}

func (m *formModel) isToggle() bool {
	return formFields[m.focus].kind == toggleField
}

// shown reports whether field f is on the form: its gate, if any, is ON.
func (m *formModel) shown(f int) bool {
	g := formFields[f].gate
	return g == 0 || m.toggles[g]
}

// moveFocus advances focus by delta (+1 or -1), skipping gated fields whose
// toggle is OFF (Hit Rate without Simulate, Depth without Recursive).
func (m *formModel) moveFocus(delta int) {
	for {
		m.focus = (m.focus + delta + fieldCount) % fieldCount
		if m.shown(m.focus) {
			return
		}
	}
}

func (m formModel) Update(msg tea.Msg) (formModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width

	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			return m.shiftFocus(+1)

		case "shift+tab", "up":
			return m.shiftFocus(-1)

		case " ":
			if m.isToggle() {
				m.toggles[m.focus] = !m.toggles[m.focus]
			}
		}
	}

	// Forward events to the focused text input.
	if !m.isToggle() {
		var cmd tea.Cmd
		m.inputs[m.focus], cmd = m.inputs[m.focus].Update(msg)
		return m, cmd
	}
	return m, nil
}

// shiftFocus moves focus by delta, blurring the text input it leaves and
// focusing the one it lands on.
func (m formModel) shiftFocus(delta int) (formModel, tea.Cmd) {
	if !m.isToggle() {
		m.inputs[m.focus].Blur()
		m.inputs[m.focus].PromptStyle = blurredStyle
		m.inputs[m.focus].TextStyle = blurredStyle
	}
	m.moveFocus(delta)
	if !m.isToggle() {
		m.inputs[m.focus].Focus()
		m.inputs[m.focus].PromptStyle = focusedStyle
		m.inputs[m.focus].TextStyle = focusedStyle
		return m, textinput.Blink
	}
	return m, nil
}

func (m formModel) View() string {
	var b strings.Builder

	b.WriteString(logo() + "\n\n")
	b.WriteString(titleStyle.Render("Configure Scan") + "\n")

	for f, spec := range formFields {
		if !m.shown(f) {
			gate := formFields[spec.gate].label
			b.WriteString(dimmedRow.Render(fmt.Sprintf("  %-20s(enable %s)", spec.label+":", gate)) + "\n")
			continue
		}
		var content string
		if spec.kind == toggleField {
			content = toggleVal(m.toggles[f])
			if m.focus == f {
				content += blurredStyle.Render("  [space to toggle]")
			}
		} else {
			content = m.inputs[f].View()
		}
		lbl := labelStyle.Render(spec.label + ":")
		if m.focus == f {
			b.WriteString(focusedStyle.Render("▸ ") + lbl + content + "\n")
		} else {
			b.WriteString("  " + lbl + content + "\n")
		}
	}

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
	text := func(f int) string { return m.inputs[f].Value() }

	rawDomain := strings.TrimSpace(text(fieldDomain))
	if rawDomain == "" {
		return formValues{}, "Domain is required"
	}
	// Same normalization as the CLI, so a pasted URL or Example.COM. scans
	// (and saves) the same canonical domain (#54).
	domain, _, err := validate.NormalizeDomain(rawDomain)
	if err != nil {
		return formValues{}, err.Error()
	}
	wl := expandHome(strings.TrimSpace(text(fieldWordlist)))
	if wl == "" {
		return formValues{}, "Wordlist path is required"
	}
	// The TUI owns stdin, so reading a wordlist from it would block forever (#55).
	if wl == wordlist.Stdin {
		return formValues{}, "Wordlist from standard input (-) is not supported in the TUI; enter a file path"
	}
	dnsServer := strings.TrimSpace(text(fieldDNSServer))
	if dnsServer == "" {
		dnsServer = validate.DefaultDNSServer
	}

	// The form only parses its text fields here; ranges and the resolver are
	// checked by scan.Options.Validate, the same validator the CLI uses (#80).
	num := func(f int, name string, blank int) int {
		s := strings.TrimSpace(text(f))
		if err != nil || s == "" {
			return blank
		}
		n, perr := strconv.Atoi(s)
		if perr != nil {
			err = fmt.Errorf("%s must be a whole number, got %q", name, text(f))
		}
		return n
	}
	concurrency := num(fieldConcurrency, "Concurrency", 0)
	timeout := num(fieldTimeout, "Timeout", 0)
	attempts := num(fieldAttempts, "Attempts", 0)
	// Hit rate only matters in simulation mode, and depth only when
	// recursive is on; otherwise their fields must not block the scan.
	hitRate := 15
	if m.shown(fieldHitRate) {
		hitRate = num(fieldHitRate, "Hit rate", 0)
	}
	depth := 1
	if m.shown(fieldDepth) {
		depth = num(fieldDepth, "Depth", 1)
	}
	rate := num(fieldRate, "Rate", 0)                    // blank means unlimited
	maxQueries := num(fieldMaxQueries, "Max queries", 0) // blank means unlimited
	var exclude []string                                 // out-of-scope names, never queried (#87)
	for _, p := range strings.Split(text(fieldExclude), ",") {
		if p = strings.TrimSpace(p); p != "" {
			exclude = append(exclude, p)
		}
	}
	if err != nil {
		return formValues{}, err.Error()
	}

	recordTypes, err := dns.ParseTypes(text(fieldTypes))
	if err != nil {
		return formValues{}, err.Error()
	}

	// Output file is optional; the format applies only to that file and is
	// validated even when no file is set so a typo is caught early.
	outputFile := expandHome(strings.TrimSpace(text(fieldOutput)))
	formatStr := strings.TrimSpace(text(fieldFormat))
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
		recursive:   m.toggles[fieldRecursive],
		depth:       depth,
		rate:        rate,
		maxQueries:  maxQueries,
		exclude:     exclude,
		noAbort:     m.toggles[fieldNoAbort],
		outputFile:  outputFile,
		format:      format,
		formatName:  formatStr,
		simulate:    m.toggles[fieldSimulate],
		force:       m.toggles[fieldForce],
	}
	if err := v.options(nil, 0).Validate(); err != nil {
		return formValues{}, scan.Render(err.Error(), settingLabel)
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
		Exclude:     v.exclude,
		NoAbort:     v.noAbort,
	}
}

// settingLabel names an engine setting as its form field (#100).
func settingLabel(s scan.Setting) string {
	for _, spec := range formFields {
		if s != "" && spec.setting == s {
			return spec.label
		}
	}
	return settingsWithoutField[s]
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
	exclude     []string
	noAbort     bool
	outputFile  string
	format      output.Format
	formatName  string
	simulate    bool
	force       bool
}
