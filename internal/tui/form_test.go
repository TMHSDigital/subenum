package tui

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/scan"
)

func TestNewFormModelDefaults(t *testing.T) {
	m := newFormModel(savedConfig{})
	if m.focus != fieldDomain {
		t.Errorf("expected initial focus on domain, got %d", m.focus)
	}
	if got := m.inputs[fieldWordlist].Value(); got != "examples/sample_wordlist.txt" {
		t.Errorf("default wordlist = %q", got)
	}
	if got := m.inputs[fieldConcurrency].Value(); got != "100" {
		t.Errorf("default concurrency = %q", got)
	}
}

func TestValidateMissingDomain(t *testing.T) {
	m := newFormModel(savedConfig{})
	m.inputs[fieldDomain].SetValue("")
	if _, errStr := m.validate(); errStr == "" {
		t.Error("expected validation error for missing domain")
	}
}

func TestValidateNonPositiveConcurrency(t *testing.T) {
	m := newFormModel(savedConfig{})
	m.inputs[fieldDomain].SetValue("example.com")
	m.inputs[fieldConcurrency].SetValue("0")
	_, errStr := m.validate()
	if !strings.Contains(errStr, "concurrency") {
		t.Errorf("expected concurrency error, got %q", errStr)
	}
}

// Empty hit rate must be accepted when Simulate is OFF (it is never used),
// and rejected when Simulate is ON.
func TestValidateHitRateOnlyWhenSimulate(t *testing.T) {
	live := newFormModel(savedConfig{})
	live.inputs[fieldDomain].SetValue("example.com")
	live.inputs[fieldHitRate].SetValue("") // blank hit rate
	live.toggles[fieldSimulate] = false
	vals, errStr := live.validate()
	if errStr != "" {
		t.Errorf("live mode should ignore hit rate, got error %q", errStr)
	}
	if vals.hitRate < 1 || vals.hitRate > 100 {
		t.Errorf("live mode should set a sane default hit rate, got %d", vals.hitRate)
	}

	sim := newFormModel(savedConfig{})
	sim.inputs[fieldDomain].SetValue("example.com")
	sim.inputs[fieldHitRate].SetValue("") // blank hit rate
	sim.toggles[fieldSimulate] = true
	if _, errStr := sim.validate(); errStr == "" {
		t.Error("simulate mode should reject blank hit rate")
	}

	sim.inputs[fieldHitRate].SetValue("500") // out of range
	if _, errStr := sim.validate(); errStr == "" {
		t.Error("simulate mode should reject out-of-range hit rate")
	}
}

func TestMoveFocusSkipsGatedFields(t *testing.T) {
	m := newFormModel(savedConfig{})

	// Both gates off: HitRate is skipped after Simulate, Depth after Recursive.
	m.toggles[fieldSimulate] = false
	m.toggles[fieldRecursive] = false

	m.focus = fieldSimulate
	m.moveFocus(+1)
	if m.focus != fieldDNSServer {
		t.Errorf("simulate OFF: expected DNSServer after Simulate, got %d", m.focus)
	}

	m.focus = fieldRecursive
	m.moveFocus(+1)
	if m.focus != fieldRate {
		t.Errorf("recursive OFF: expected Rate after Recursive (Depth skipped), got %d", m.focus)
	}

	// Gates on: the previously skipped fields are now reachable.
	m.toggles[fieldSimulate] = true
	m.focus = fieldSimulate
	m.moveFocus(+1)
	if m.focus != fieldHitRate {
		t.Errorf("simulate ON: expected HitRate after Simulate, got %d", m.focus)
	}

	m.toggles[fieldRecursive] = true
	m.focus = fieldRecursive
	m.moveFocus(+1)
	if m.focus != fieldDepth {
		t.Errorf("recursive ON: expected Depth after Recursive, got %d", m.focus)
	}
}

func TestValidateRejectsBadRecordType(t *testing.T) {
	m := newFormModel(savedConfig{})
	m.inputs[fieldDomain].SetValue("example.com")
	m.inputs[fieldTypes].SetValue("A,MX")
	if _, errStr := m.validate(); errStr == "" {
		t.Error("expected validation error for unsupported record type MX")
	}
}

func TestValidateDepthGatedOnRecursive(t *testing.T) {
	m := newFormModel(savedConfig{})
	m.inputs[fieldDomain].SetValue("example.com")
	m.inputs[fieldDepth].SetValue("not-a-number")

	// Recursive OFF: bad depth is ignored, defaults to 1.
	m.toggles[fieldRecursive] = false
	vals, errStr := m.validate()
	if errStr != "" {
		t.Errorf("recursive OFF should ignore depth, got %q", errStr)
	}
	if vals.depth != 1 {
		t.Errorf("expected default depth 1 when recursive off, got %d", vals.depth)
	}

	// Recursive ON: bad depth is rejected.
	m.toggles[fieldRecursive] = true
	if _, errStr := m.validate(); errStr == "" {
		t.Error("recursive ON should reject non-numeric depth")
	}
}

// TestValidateMaxQueriesAndNoAbort covers #35: the TUI can set the query cap
// and no-abort, so a large recursive scan no longer needs Force (which also
// disables the wildcard abort).
func TestValidateMaxQueriesAndNoAbort(t *testing.T) {
	m := newFormModel(savedConfig{})
	m.inputs[fieldDomain].SetValue("example.com")
	m.inputs[fieldMaxQueries].SetValue("2500")
	m.toggles[fieldNoAbort] = true
	vals, errStr := m.validate()
	if errStr != "" {
		t.Fatalf("validate: %s", errStr)
	}
	if vals.maxQueries != 2500 || !vals.noAbort || vals.force {
		t.Errorf("got maxQueries=%d noAbort=%v force=%v", vals.maxQueries, vals.noAbort, vals.force)
	}

	m.inputs[fieldMaxQueries].SetValue("-1")
	if _, errStr := m.validate(); !strings.Contains(errStr, "max queries") {
		t.Errorf("negative max queries: got %q", errStr)
	}

	// The new toggle is reachable and flips with space.
	m.focus = fieldForce
	m.moveFocus(+1)
	if m.focus != fieldNoAbort || !m.isToggle() {
		t.Errorf("focus after Force = %d, want No Abort toggle", m.focus)
	}
}

// TestValidateNormalizesDomain covers #54 for the TUI: a pasted URL or mixed
// case domain scans the same canonical name as the CLI.
func TestValidateNormalizesDomain(t *testing.T) {
	for _, in := range []string{"https://Example.COM/", "Example.COM.", "example.com"} {
		m := newFormModel(savedConfig{})
		m.inputs[fieldDomain].SetValue(in)
		vals, errStr := m.validate()
		if errStr != "" {
			t.Fatalf("%q: unexpected error %q", in, errStr)
		}
		if vals.domain != "example.com" {
			t.Errorf("%q: domain = %q, want example.com", in, vals.domain)
		}
	}
}

// TestFormBuildsSharedConfig covers #80: the TUI builds its scan.Config with
// the shared scan.Options builder. main_test.go asserts the CLI produces this
// same Config from the equivalent flags.
func TestFormBuildsSharedConfig(t *testing.T) {
	m := newFormModel(savedConfig{})
	for f, v := range map[int]string{
		fieldDomain: "example.com", fieldWordlist: "wl.txt", fieldHitRate: "30", fieldDNSServer: "1.1.1.1:53",
		fieldConcurrency: "50", fieldTimeout: "800", fieldAttempts: "2", fieldTypes: "A,CNAME", fieldDepth: "2",
		fieldRate: "100", fieldOutput: "", fieldMaxQueries: "500",
	} {
		m.inputs[f].SetValue(v)
	}
	for _, f := range []int{fieldSimulate, fieldForce, fieldRecursive, fieldNoAbort} {
		m.toggles[f] = true
	}
	vals, errStr := m.validate()
	if errStr != "" {
		t.Fatalf("validate: %s", errStr)
	}
	got := vals.options([]string{"www", "mail"}, 7).Config()
	want := scan.Config{
		Domain: "example.com", Entries: []string{"www", "mail"}, Concurrency: 50,
		Timeout: 800 * time.Millisecond, DNSServer: "1.1.1.1:53", Simulate: true, HitRate: 30,
		Seed: 7, Attempts: 2, Force: true, Types: []string{"A", "CNAME"}, Recursive: true,
		Depth: 2, Rate: 100, MaxQueries: 500, NoAbort: true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TUI config:\n got %+v\nwant %+v", got, want)
	}
}

// TestValidateExclude covers #87 in the TUI: the Exclude field reaches the
// scan config, and an invalid pattern is rejected on the form.
func TestValidateExclude(t *testing.T) {
	m := newFormModel(savedConfig{})
	m.inputs[fieldDomain].SetValue("example.com")
	m.inputs[fieldExclude].SetValue(" vpn.example.com , *.corp.example.com ")
	vals, errStr := m.validate()
	if errStr != "" {
		t.Fatalf("validate: %s", errStr)
	}
	if got := vals.options(nil, 0).Config().Exclude; !reflect.DeepEqual(got, []string{"vpn.example.com", "*.corp.example.com"}) {
		t.Errorf("Exclude = %q", got)
	}
	m.inputs[fieldExclude].SetValue("not a domain")
	// The engine's setting token is rendered as the form field (#100).
	if _, errStr := m.validate(); !strings.Contains(errStr, "invalid Exclude pattern") {
		t.Errorf("invalid pattern: got %q", errStr)
	}
}

// TestSettingLabelsCoverEverySetting covers #100: the TUI names every engine
// setting, so no {token} reaches the screen.
func TestSettingLabelsCoverEverySetting(t *testing.T) {
	for _, s := range scan.Settings {
		if settingLabel(s) == "" {
			t.Errorf("setting %q has no form label", s)
		}
	}
}

// TestFormFieldSpec covers #161 and #160: every formFields entry is complete,
// a gate always names a toggle, and a field with an engine setting takes its
// label and flag from scan's table rather than its own.
func TestFormFieldSpec(t *testing.T) {
	for f, spec := range formFields {
		if spec.name() == "" {
			t.Errorf("field %d has no label", f)
		}
		if spec.setting != "" && (spec.label != "" || spec.flag != "") {
			t.Errorf("field %q names its setting's label or flag itself", spec.name())
		}
		if spec.saved == nil {
			t.Errorf("field %q has no saved config slot", spec.name())
			continue
		}
		var c savedConfig
		switch spec.saved(&c).(type) {
		case *string, *int:
			if spec.kind != textField || spec.placeholder == "" {
				t.Errorf("text field %q is not a text field or lacks a placeholder", spec.name())
			}
		case *bool:
			if spec.kind != toggleField || spec.gate != 0 {
				t.Errorf("toggle %q is not a toggle or is gated", spec.name())
			}
		default:
			t.Errorf("field %q is saved in an unsupported type", spec.name())
		}
		if spec.gate != 0 && formFields[spec.gate].kind != toggleField {
			t.Errorf("field %q is gated on %q, which is not a toggle", spec.name(), formFields[spec.gate].name())
		}
	}
}

// TestFormViewRows pins the default form's rows (ANSI stripped), so the
// table-driven View keeps the order, labels, defaults and gate hints (#161).
func TestFormViewRows(t *testing.T) {
	ansi := regexp.MustCompile("\x1b\\[[0-9;?]*[a-zA-Z]")
	var rows []string
	for _, line := range strings.Split(ansi.ReplaceAllString(newFormModel(savedConfig{}).View(), ""), "\n") {
		if line = strings.TrimRight(line, " "); strings.Contains(line, ":") {
			rows = append(rows, line)
		}
	}
	want := []string{
		"▸ Domain*:          > e.g. example.com",
		"  Wordlist*:        > examples/sample_wordlist.txt",
		"  Simulate:         OFF",
		"  Hit Rate (%):       (enable Simulate)",
		"  DNS Server:       > 8.8.8.8:53",
		"  Concurrency:      > 100",
		"  Timeout (ms):     > 1000",
		"  Attempts:         > 1",
		"  Record Types:     > A,AAAA",
		"  Recursive:        OFF",
		"  Depth:              (enable Recursive)",
		"  Rate (qps):       > 0",
		"  Max Names:        > 0",
		"  Exclude:          > optional, e.g. vpn.example.com,*.corp.example.com",
		"  Output File:      > optional, e.g. results.txt",
		"  Format:           > text",
		"  Force:            OFF",
		"  No Abort:         OFF",
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("form rows:\n got %q\nwant %q", rows, want)
	}
}

// TestWithSettingsSeedsEveryFlaggedField covers #160: a SUBENUM_* or config
// file value for each field's flag reaches that field and no other.
func TestWithSettingsSeedsEveryFlaggedField(t *testing.T) {
	blank := newFormModel(savedConfig{})
	for f, spec := range formFields {
		flag := spec.flagName()
		if flag == "" {
			continue
		}
		v := "7"
		if spec.kind == toggleField {
			v = "true"
		}
		m := newFormModel(withSettings(savedConfig{}, map[string]string{flag: v}))
		for g := range formFields {
			changed := m.inputs[g].Value() != blank.inputs[g].Value() || m.toggles[g] != blank.toggles[g]
			if want := g == f; changed != want {
				t.Errorf("-%s=%s: field %q changed = %v, want %v", flag, v, formFields[g].name(), changed, want)
			}
		}
	}
}
