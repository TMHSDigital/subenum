package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

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
	fieldResolvers       // -r resolver pool file (#195)
	fieldRatePerResolver // -rate-per-resolver; only used with a pool
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

// formField describes one form row. The form is built, navigated, rendered,
// labelled, seeded and saved from formFields, so adding a field is one
// constant and one entry (plus reading it in validate).
type formField struct {
	// setting is the engine setting this field sets, if any; its row label
	// and flag then come from scan's setting table (#160).
	setting     scan.Setting
	label       string    // row label, for a field with no setting
	flag        string    // CLI flag (config key) that seeds it, for a field with no setting
	kind        fieldKind // text input or toggle
	placeholder string    // text fields: hint shown while empty
	def         string    // text fields: value when the saved one is empty or zero
	// saved points at the savedConfig field this row is remembered in: a
	// *string or *int for a text field, a *bool for a toggle.
	saved func(*savedConfig) any
	// gate is the toggle that must be ON for this field to be shown and
	// reachable. Zero means always shown (fieldDomain is never a toggle).
	gate int
}

// formFields is indexed by the field constants.
var formFields = [fieldCount]formField{
	fieldDomain: {label: "Domain*", kind: textField, placeholder: "e.g. example.com",
		saved: func(c *savedConfig) any { return &c.Domain }},
	fieldWordlist: {label: "Wordlist*", flag: "w", kind: textField, placeholder: "e.g. examples/sample_wordlist.txt", def: "examples/sample_wordlist.txt",
		saved: func(c *savedConfig) any { return &c.Wordlist }},
	fieldSimulate: {label: "Simulate", flag: "simulate", kind: toggleField,
		saved: func(c *savedConfig) any { return &c.Simulate }},
	fieldHitRate: {setting: scan.SettingHitRate, kind: textField, placeholder: "1–100", def: "15", gate: fieldSimulate,
		saved: func(c *savedConfig) any { return &c.HitRate }},
	fieldDNSServer: {label: "DNS Server", flag: "dns-server", kind: textField, placeholder: "e.g. 8.8.8.8:53", def: validate.DefaultDNSServer,
		saved: func(c *savedConfig) any { return &c.DNSServer }},
	fieldResolvers: {label: "Resolver Pool", flag: "r", kind: textField, placeholder: "optional, file of resolver addresses",
		saved: func(c *savedConfig) any { return &c.Resolvers }},
	fieldRatePerResolver: {label: "Rate/Resolver", flag: "rate-per-resolver", kind: textField, placeholder: "0 = unlimited", def: "0",
		saved: func(c *savedConfig) any { return &c.RatePerResolver }},
	fieldConcurrency: {setting: scan.SettingConcurrency, kind: textField, placeholder: "e.g. 100", def: "100",
		saved: func(c *savedConfig) any { return &c.Concurrency }},
	fieldTimeout: {setting: scan.SettingTimeout, kind: textField, placeholder: "e.g. 1000", def: "1000",
		saved: func(c *savedConfig) any { return &c.TimeoutMs }},
	fieldAttempts: {setting: scan.SettingAttempts, kind: textField, placeholder: "e.g. 1", def: "1",
		saved: func(c *savedConfig) any { return &c.Attempts }},
	fieldTypes: {label: "Record Types", flag: "type", kind: textField, placeholder: "e.g. A,AAAA,CNAME", def: "A,AAAA",
		saved: func(c *savedConfig) any { return &c.Types }},
	fieldRecursive: {setting: scan.SettingRecursive, kind: toggleField,
		saved: func(c *savedConfig) any { return &c.Recursive }},
	fieldDepth: {setting: scan.SettingDepth, kind: textField, placeholder: "e.g. 2", def: "1", gate: fieldRecursive,
		saved: func(c *savedConfig) any { return &c.Depth }},
	fieldRate: {setting: scan.SettingRate, kind: textField, placeholder: "0 = unlimited", def: "0",
		saved: func(c *savedConfig) any { return &c.Rate }},
	fieldMaxQueries: {setting: scan.SettingMaxQueries, kind: textField, placeholder: "0 = unlimited", def: "0",
		saved: func(c *savedConfig) any { return &c.MaxQueries }},
	fieldExclude: {setting: scan.SettingExclude, kind: textField, placeholder: "optional, e.g. vpn.example.com,*.corp.example.com",
		saved: func(c *savedConfig) any { return &c.Exclude }},
	fieldOutput: {label: "Output File", flag: "o", kind: textField, placeholder: "optional, e.g. results.txt",
		saved: func(c *savedConfig) any { return &c.Output }},
	fieldFormat: {label: "Format", flag: "format", kind: textField, placeholder: "text, json, jsonl, csv", def: "text",
		saved: func(c *savedConfig) any { return &c.Format }},
	fieldForce: {setting: scan.SettingForce, kind: toggleField,
		saved: func(c *savedConfig) any { return &c.Force }},
	fieldNoAbort: {label: "No Abort", flag: "no-abort", kind: toggleField,
		saved: func(c *savedConfig) any { return &c.NoAbort }},
}

// name is the field's row label.
func (f formField) name() string {
	if f.setting != "" {
		return scan.Label(f.setting)
	}
	return f.label
}

// flagName is the flag (and config file key) whose value seeds the field, or
// "" for a field no flag sets.
func (f formField) flagName() string {
	if f.setting != "" {
		return f.setting.Names().Flag
	}
	return f.flag
}

// value is a text field's initial value: the saved one, or the default when
// that is empty or not positive.
func (f formField) value(c savedConfig) string {
	switch p := f.saved(&c).(type) {
	case *string:
		if *p != "" {
			return *p
		}
	case *int:
		if *p > 0 {
			return strconv.Itoa(*p)
		}
	}
	return f.def
}

// on is a toggle's initial state.
func (f formField) on(c savedConfig) bool {
	p, _ := f.saved(&c).(*bool)
	return p != nil && *p
}

// set stores a flag value in the field's savedConfig slot. A value that does
// not parse stores the zero value, which the form then shows as the default.
func (f formField) set(c *savedConfig, v string) {
	switch p := f.saved(c).(type) {
	case *string:
		*p = v
	case *int:
		*p, _ = strconv.Atoi(v)
	case *bool:
		*p, _ = strconv.ParseBool(v)
	}
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

// inputView renders a text field. Inputs have no width, so a value is never
// cut, but bubbles v2's textinput shows only the first character of a
// placeholder when its width is 0; an empty field is rendered from a copy
// sized to show the placeholder whole, without padding.
func inputView(ti textinput.Model) string {
	if ti.Value() == "" && ti.Placeholder != "" {
		ti.SetWidth(max(0, lipgloss.Width(ti.Placeholder)-1))
	}
	return ti.View()
}

// inputStyles colours a text field's prompt and text by focus: the input
// switches between the two states itself.
func inputStyles() textinput.Styles {
	s := textinput.DefaultStyles(true)
	s.Focused.Prompt, s.Focused.Text = focusedStyle, focusedStyle
	s.Blurred.Prompt, s.Blurred.Text = blurredStyle, blurredStyle
	return s
}

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
			ti.SetStyles(inputStyles())
			m.inputs[f] = ti
		case toggleField:
			m.toggles[f] = spec.on(saved)
		}
	}

	// Focus domain on start - cursor blink cmd returned from Init.
	m.inputs[fieldDomain].Focus()

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

	case tea.KeyPressMsg:
		switch msg.String() {
		case "tab", "down":
			return m.shiftFocus(+1)

		case "shift+tab", "up":
			return m.shiftFocus(-1)

		case "space":
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
	}
	m.moveFocus(delta)
	if !m.isToggle() {
		return m, m.inputs[m.focus].Focus()
	}
	return m, nil
}

func (m formModel) View() string {
	var b strings.Builder

	b.WriteString(logo() + "\n\n")
	b.WriteString(titleStyle.Render("Configure Scan") + "\n")

	for f, spec := range formFields {
		if !m.shown(f) {
			gate := formFields[spec.gate].name()
			b.WriteString(dimmedRow.Render(fmt.Sprintf("  %-20s(enable %s)", spec.name()+":", gate)) + "\n")
			continue
		}
		var content string
		if spec.kind == toggleField {
			content = toggleVal(m.toggles[f])
			if m.focus == f {
				content += blurredStyle.Render("  [space to toggle]")
			}
		} else {
			content = inputView(m.inputs[f])
		}
		lbl := labelStyle.Render(spec.name() + ":")
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
	resolvers := expandHome(strings.TrimSpace(text(fieldResolvers)))
	if resolvers == wordlist.Stdin {
		return formValues{}, "Resolver pool from standard input (-) is not supported in the TUI; enter a file path"
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
	ratePerResolver := num(fieldRatePerResolver, formFields[fieldRatePerResolver].name(), 0)
	if err == nil && ratePerResolver < 0 {
		err = fmt.Errorf("%s must be 0 (unlimited) or positive, got %d", formFields[fieldRatePerResolver].name(), ratePerResolver)
	}
	var exclude []string // out-of-scope names, never queried (#87)
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
		domain:          domain,
		wordlist:        wl,
		dnsServer:       dnsServer,
		resolvers:       resolvers,
		ratePerResolver: ratePerResolver,
		concurrency:     concurrency,
		timeoutMs:       timeout,
		attempts:        attempts,
		hitRate:         hitRate,
		recordTypes:     recordTypes,
		recursive:       m.toggles[fieldRecursive],
		depth:           depth,
		rate:            rate,
		maxQueries:      maxQueries,
		exclude:         exclude,
		noAbort:         m.toggles[fieldNoAbort],
		outputFile:      outputFile,
		format:          format,
		formatName:      formatStr,
		simulate:        m.toggles[fieldSimulate],
		force:           m.toggles[fieldForce],
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
func settingLabel(s scan.Setting) string { return scan.Label(s) }

type formValues struct {
	domain          string
	wordlist        string
	dnsServer       string
	resolvers       string // resolver pool file; "" means the single DNS server
	ratePerResolver int
	concurrency     int
	timeoutMs       int
	attempts        int
	hitRate         int
	recordTypes     []string
	recursive       bool
	depth           int
	rate            int
	maxQueries      int
	exclude         []string
	noAbort         bool
	outputFile      string
	format          output.Format
	formatName      string
	simulate        bool
	force           bool
}
