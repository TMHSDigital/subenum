package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/validate"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// Form fields in tab order. Each constant is both the field's position on the
// form and its index into formFields, formModel.inputs and formModel.toggles.
const (
	fieldDomain = iota
	fieldWordlist
	fieldSources // -sources passive sources (#274)
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
	fieldDepth   // only reachable when Recursive is ON
	fieldPermute // -permute (#274)
	fieldRate
	fieldAutoRate // -auto-rate (#274)
	fieldMaxQueries
	fieldMaxDuration // -max-duration (#274)
	fieldExclude
	fieldOutput
	fieldFormat
	fieldForce
	fieldNoAbort
	fieldRetryIncon // -retry-inconclusive (#274)
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
// constant, one entry and one savedConfig field, plus reading it in validate:
// into scan.Options if the engine takes it, else into formValues.
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
	fieldWordlist: {label: "Wordlist", flag: "w", kind: textField, placeholder: "empty = bundled top-5000 list",
		saved: func(c *savedConfig) any { return &c.Wordlist }},
	fieldSources: {label: "Sources", flag: "sources", kind: textField, placeholder: "optional, " + strings.Join(passive.Known, ","),
		saved: func(c *savedConfig) any { return &c.Sources }},
	fieldSimulate: {label: "Simulate", flag: "simulate", kind: toggleField,
		saved: func(c *savedConfig) any { return &c.Simulate }},
	fieldHitRate: {setting: scan.SettingHitRate, kind: textField, placeholder: "1–100", def: strconv.Itoa(scan.DefaultHitRate), gate: fieldSimulate,
		saved: func(c *savedConfig) any { return &c.HitRate }},
	fieldDNSServer: {label: "DNS Server", flag: "dns-server", kind: textField, placeholder: "e.g. 8.8.8.8:53", def: validate.DefaultDNSServer,
		saved: func(c *savedConfig) any { return &c.DNSServer }},
	fieldResolvers: {label: "Resolver Pool", flag: "r", kind: textField, placeholder: "optional, file of resolver addresses",
		saved: func(c *savedConfig) any { return &c.Resolvers }},
	fieldRatePerResolver: {setting: scan.SettingRatePerRes, kind: textField, placeholder: "0 = unlimited", def: "0",
		saved: func(c *savedConfig) any { return &c.RatePerResolver }},
	fieldConcurrency: {setting: scan.SettingConcurrency, kind: textField, placeholder: "e.g. 100", def: strconv.Itoa(scan.DefaultConcurrency),
		saved: func(c *savedConfig) any { return &c.Concurrency }},
	fieldTimeout: {setting: scan.SettingTimeout, kind: textField, placeholder: "e.g. 1000", def: strconv.Itoa(scan.DefaultTimeoutMs),
		saved: func(c *savedConfig) any { return &c.TimeoutMs }},
	fieldAttempts: {setting: scan.SettingAttempts, kind: textField, placeholder: "e.g. 1", def: "1",
		saved: func(c *savedConfig) any { return &c.Attempts }},
	fieldTypes: {label: "Record Types", flag: "type", kind: textField, placeholder: "e.g. A,AAAA,CNAME", def: "A,AAAA",
		saved: func(c *savedConfig) any { return &c.Types }},
	fieldRecursive: {setting: scan.SettingRecursive, kind: toggleField,
		saved: func(c *savedConfig) any { return &c.Recursive }},
	fieldDepth: {setting: scan.SettingDepth, kind: textField, placeholder: "e.g. 2", def: "1", gate: fieldRecursive,
		saved: func(c *savedConfig) any { return &c.Depth }},
	fieldPermute: {label: "Permute", flag: "permute", kind: toggleField,
		saved: func(c *savedConfig) any { return &c.Permute }},
	fieldRate: {setting: scan.SettingRate, kind: textField, placeholder: "0 = unlimited", def: "0",
		saved: func(c *savedConfig) any { return &c.Rate }},
	fieldAutoRate: {label: "Auto Rate", flag: "auto-rate", kind: toggleField,
		saved: func(c *savedConfig) any { return &c.AutoRate }},
	fieldMaxQueries: {setting: scan.SettingMaxQueries, kind: textField, placeholder: "0 = unlimited", def: "0",
		saved: func(c *savedConfig) any { return &c.MaxQueries }},
	fieldMaxDuration: {setting: scan.SettingMaxDuration, kind: textField, placeholder: "optional, e.g. 20m",
		saved: func(c *savedConfig) any { return &c.MaxDuration }},
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
	fieldRetryIncon: {label: "Retry Inconclusive", flag: "retry-inconclusive", kind: toggleField,
		saved: func(c *savedConfig) any { return &c.RetryInconclusive }},
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
	labelStyle    = lipgloss.NewStyle().Width(20) // fits "Retry Inconclusive:"
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
	asking  bool // the load also asks the passive sources (#274)
	width   int  // terminal size, 0 until the first size message
	height  int
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
		m.width, m.height = msg.Width, msg.Height

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

// View renders the form. On a terminal too short for all of it the logo is
// dropped, then the field rows scroll to keep the focused one in view; the
// error or loading line and the key hints are always drawn (#287).
func (m formModel) View() string {
	title := titleStyle.Render("Configure Scan") + "\n"
	header := logo() + "\n\n" + title
	rows := m.rows()
	footer := m.footer()

	heights := make([]int, len(rows))
	total := 0
	for i, r := range rows {
		heights[i] = m.lines(r)
		total += heights[i]
	}
	// Before the first size message the height is unknown: draw everything.
	if m.height <= 0 || m.lines(header)+total+m.lines(footer) <= m.height {
		return header + strings.Join(rows, "\n") + "\n" + footer
	}
	header = title
	avail := m.height - m.lines(header) - m.lines(footer)
	if total <= avail {
		return header + strings.Join(rows, "\n") + "\n" + footer
	}

	// Two of the lines left say how many fields are off each end.
	lo, hi := rowWindow(heights, m.focus, max(1, avail-2))
	var b strings.Builder
	b.WriteString(header)
	if lo > 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  ↑ %d more fields", lo)))
	}
	b.WriteString("\n" + strings.Join(rows[lo:hi], "\n") + "\n")
	if hi < len(rows) {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  ↓ %d more fields", len(rows)-hi)))
	}
	b.WriteString("\n" + footer)
	return b.String()
}

// lines counts the terminal lines s takes, a line wider than the terminal
// wrapping onto the next. A trailing newline does not start another line.
func (m formModel) lines(s string) int {
	n := 0
	for _, l := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		n++
		if m.width > 0 {
			n += max(0, lipgloss.Width(l)-1) / m.width
		}
	}
	return n
}

// rowWindow picks the rows [lo, hi) to draw in avail lines so that row focus
// is among them. It keeps to the top of the form while focus fits there, then
// to the bottom, and otherwise grows the window around focus.
func rowWindow(heights []int, focus, avail int) (lo, hi int) {
	used := 0
	for hi < len(heights) && used+heights[hi] <= avail {
		used += heights[hi]
		hi++
	}
	if focus < hi {
		return 0, hi
	}
	lo, hi, used = len(heights), len(heights), 0
	for lo > 0 && used+heights[lo-1] <= avail {
		lo--
		used += heights[lo]
	}
	if focus >= lo {
		return lo, hi
	}
	lo, hi, used = focus, focus+1, heights[focus]
	for grew := true; grew; {
		grew = false
		if lo > 0 && used+heights[lo-1] <= avail {
			lo--
			used += heights[lo]
			grew = true
		}
		if hi < len(heights) && used+heights[hi] <= avail {
			used += heights[hi]
			hi++
			grew = true
		}
	}
	return lo, hi
}

// rows renders one line per form field, indexed by the field constants.
func (m formModel) rows() []string {
	rows := make([]string, 0, fieldCount)
	for f, spec := range formFields {
		if !m.shown(f) {
			gate := formFields[spec.gate].name()
			// The label's width plus the "> " of a text field, so the hint
			// lines up with the values.
			rows = append(rows, dimmedRow.Render(fmt.Sprintf("  %-22s(enable %s)", spec.name()+":", gate)))
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
			rows = append(rows, focusedStyle.Render("▸ ")+lbl+content)
		} else {
			rows = append(rows, "  "+lbl+content)
		}
	}
	return rows
}

// footer renders what follows the field rows: the validation error or the
// loading line, if any, and the key hints.
func (m formModel) footer() string {
	var b strings.Builder

	if m.err != "" {
		b.WriteString("\n" + errorStyle.Render("  ✗ "+m.err) + "\n")
	}
	if m.loading {
		note := "  Loading wordlist..."
		if m.asking {
			note = "  Loading wordlist and asking the passive sources..."
		}
		b.WriteString("\n" + dimStyle.Render(note) + "\n")
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

// remembered is the form as last.json keeps it, built from formFields: every
// toggle, and every text field trimmed, or its default when it is blank or
// hidden. validate then stores the fields it normalizes as it read them.
func (m *formModel) remembered() savedConfig {
	var sc savedConfig
	for f, spec := range formFields {
		if spec.kind == toggleField {
			spec.set(&sc, strconv.FormatBool(m.toggles[f]))
			continue
		}
		v := strings.TrimSpace(m.inputs[f].Value())
		if v == "" || !m.shown(f) {
			v = spec.def
		}
		spec.set(&sc, v)
	}
	return sc
}

// validate checks all inputs and returns a scan config or an error string.
func (m *formModel) validate() (formValues, string) {
	text := func(f int) string { return m.inputs[f].Value() }
	// What the next session's form shows is the value the scan ran with, not
	// the text as typed: keep stores a field's normalized value.
	saved := m.remembered()
	keep := func(f int, v string) { formFields[f].set(&saved, v) }
	// A file path, with a leading "~" expanded.
	path := func(f int) string {
		p := expandHome(strings.TrimSpace(text(f)))
		keep(f, p)
		return p
	}

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
	keep(fieldDomain, domain)
	// An empty Wordlist field scans with the bundled list, the way a missing
	// -w does on the command line (#288).
	wl := path(fieldWordlist)
	// The TUI owns stdin, so reading a wordlist from it would block forever (#55).
	if wl == wordlist.Stdin {
		return formValues{}, "Wordlist from standard input (-) is not supported in the TUI; enter a file path"
	}
	// Same parser as -sources, so the form takes the names the CLI does (#274).
	sources, err := passive.ParseList(text(fieldSources))
	if err != nil {
		return formValues{}, formFields[fieldSources].name() + ": " + err.Error()
	}
	keep(fieldSources, strings.Join(sources, ","))
	dnsServer := strings.TrimSpace(text(fieldDNSServer))
	if dnsServer == "" {
		dnsServer = validate.DefaultDNSServer
	}
	resolvers := path(fieldResolvers)
	if resolvers == wordlist.Stdin {
		return formValues{}, "Resolver pool from standard input (-) is not supported in the TUI; enter a file path"
	}

	// The form only parses its text fields here; ranges and the resolver are
	// checked by scan.Options.Validate, the same validator the CLI uses (#80).
	num := func(f int, name string, blank int) int {
		s := strings.TrimSpace(text(f))
		if err != nil || s == "" {
			keep(f, strconv.Itoa(blank))
			return blank
		}
		n, perr := strconv.Atoi(s)
		if perr != nil {
			err = fmt.Errorf("%s must be a whole number, got %q", name, text(f))
		}
		keep(f, strconv.Itoa(n))
		return n
	}
	concurrency := num(fieldConcurrency, "Concurrency", 0)
	timeout := num(fieldTimeout, "Timeout", 0)
	attempts := num(fieldAttempts, "Attempts", 0)
	// Hit rate only matters in simulation mode, and depth only when
	// recursive is on; otherwise their fields must not block the scan.
	hitRate := scan.DefaultHitRate
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
	var maxDuration time.Duration // blank means unlimited, as -max-duration 0
	if s := strings.TrimSpace(text(fieldMaxDuration)); err == nil && s != "" {
		var perr error
		if maxDuration, perr = time.ParseDuration(s); perr != nil {
			err = fmt.Errorf("%s must be a duration such as 20m or 1h30m, got %q", formFields[fieldMaxDuration].name(), s)
		}
	}
	var exclude []string // out-of-scope names, never queried (#87)
	for _, p := range strings.Split(text(fieldExclude), ",") {
		if p = strings.TrimSpace(p); p != "" {
			exclude = append(exclude, p)
		}
	}
	keep(fieldMaxDuration, durationText(maxDuration))
	keep(fieldExclude, strings.Join(exclude, ","))
	if err != nil {
		return formValues{}, err.Error()
	}

	recordTypes, err := dns.ParseTypes(text(fieldTypes))
	if err != nil {
		return formValues{}, err.Error()
	}
	keep(fieldTypes, strings.Join(recordTypes, ","))

	// Output file is optional; the format applies only to that file and is
	// validated even when no file is set so a typo is caught early.
	outputFile := path(fieldOutput)
	formatStr := strings.TrimSpace(text(fieldFormat))
	if formatStr == "" {
		formatStr = "text"
	}
	format, err := output.ParseFormat(formatStr)
	if err != nil {
		return formValues{}, err.Error()
	}

	v := formValues{
		Options: scan.Options{
			Config: scan.Config{
				Domain:      domain,
				Concurrency: concurrency,
				Timeout:     time.Duration(timeout) * time.Millisecond,
				DNSServer:   dnsServer,
				Simulate:    m.toggles[fieldSimulate],
				HitRate:     hitRate,
				Attempts:    attempts,
				Force:       m.toggles[fieldForce],
				Types:       recordTypes,
				Recursive:   m.toggles[fieldRecursive],
				Depth:       depth,
				Rate:        rate,
				AutoRate:    m.toggles[fieldAutoRate],
				MaxQueries:  maxQueries,
				Exclude:     exclude,
				NoAbort:     m.toggles[fieldNoAbort],

				RetryInconclusive: m.toggles[fieldRetryIncon],
			},
			MaxDuration:     maxDuration,
			RatePerResolver: ratePerResolver,
		},
		wordlist:   wl,
		sources:    sources,
		resolvers:  resolvers,
		permute:    m.toggles[fieldPermute],
		outputFile: outputFile,
		format:     format,
		saved:      saved,
	}
	if err := v.Validate(); err != nil {
		return formValues{}, scan.Render(err.Error(), settingLabel)
	}
	return v, ""
}

// options is the scan options for one pass over entries. They are the type
// the CLI also builds, so both front ends share one validator and one Config
// builder (#80).
func (v formValues) options(entries []string, seed uint64) scan.Options {
	opts := v.Options
	opts.Entries, opts.Seed = entries, seed
	return opts
}

// settingLabel names an engine setting as its form field (#100).
func settingLabel(s scan.Setting) string { return scan.Label(s) }

// formValues is a validated form: the scan options it sets, the values the
// engine does not take, and the form as last.json remembers it.
type formValues struct {
	// Options holds the engine settings. Entries and Seed are set per pass by
	// options, Pool and Deadline by beginScan; MaxDuration 0 means unlimited.
	scan.Options
	wordlist   string
	sources    []string // passive sources asked before the scan, in passive.Known order
	resolvers  string   // resolver pool file; "" means the single DNS server
	permute    bool     // a second pass over permutations of the names found
	outputFile string
	format     output.Format
	saved      savedConfig // what saveConfig writes for the next session
}
