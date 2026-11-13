package tui

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// Key handling for the form and the root model (#172).

var (
	keyTab       = tea.KeyPressMsg{Code: tea.KeyTab}
	keyShiftTab  = tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
	keyDown      = tea.KeyPressMsg{Code: tea.KeyDown}
	keyUp        = tea.KeyPressMsg{Code: tea.KeyUp}
	keySpace     = tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
	keyEnter     = tea.KeyPressMsg{Code: tea.KeyEnter}
	keyEsc       = tea.KeyPressMsg{Code: tea.KeyEscape}
	keyBackspace = tea.KeyPressMsg{Code: tea.KeyBackspace}
	keyCtrlC     = tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
	keyCtrlR     = tea.KeyPressMsg{Code: 'r', Mod: tea.ModCtrl}
)

// typeText is the key press that types s, as a terminal reports it.
func typeText(s string) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: []rune(s)[0], Text: s}
}

// focusedInputs counts the text inputs that have focus.
func focusedInputs(m formModel) int {
	n := 0
	for _, in := range m.inputs {
		if in.Focused() {
			n++
		}
	}
	return n
}

func TestFormTabOrderWrapsAndSkipsGatedFields(t *testing.T) {
	m := newFormModel(savedConfig{})
	var order []int
	for range fieldCount {
		var cmd tea.Cmd
		m, cmd = m.Update(keyTab)
		order = append(order, m.focus)
		if formFields[m.focus].kind == textField {
			if cmd == nil || !m.inputs[m.focus].Focused() {
				t.Fatalf("tab onto text field %d: cmd=%v focused=%v", m.focus, cmd != nil, m.inputs[m.focus].Focused())
			}
		} else if cmd != nil {
			t.Fatalf("tab onto toggle %d returned a command", m.focus)
		}
		if focusedInputs(m) > 1 {
			t.Fatalf("%d inputs focused after tab to %d", focusedInputs(m), m.focus)
		}
	}
	for _, f := range order {
		if f == fieldHitRate || f == fieldDepth {
			t.Fatalf("tab visited gated field %d with its toggle off: %v", f, order)
		}
	}
	// 18 fields less the 2 gated ones: the 16th tab is back on the domain.
	if order[fieldCount-3] != fieldDomain {
		t.Fatalf("tab order %v does not wrap to the domain after 16 steps", order)
	}

	// Backwards from the domain wraps to the last field.
	m = newFormModel(savedConfig{})
	m, _ = m.Update(keyShiftTab)
	if m.focus != fieldNoAbort || m.inputs[fieldDomain].Focused() {
		t.Fatalf("shift+tab from the domain: focus=%d domain focused=%v", m.focus, m.inputs[fieldDomain].Focused())
	}
	m, _ = m.Update(keyUp)
	if m.focus != fieldForce {
		t.Fatalf("up: focus=%d, want Force", m.focus)
	}
	m, _ = m.Update(keyDown)
	if m.focus != fieldNoAbort {
		t.Fatalf("down: focus=%d, want No Abort", m.focus)
	}
}

func TestFormTabVisitsGatedFieldsWhenEnabled(t *testing.T) {
	m := newFormModel(savedConfig{Simulate: true, Recursive: true})
	seen := map[int]bool{}
	for range fieldCount {
		m, _ = m.Update(keyTab)
		seen[m.focus] = true
	}
	if len(seen) != fieldCount || !seen[fieldHitRate] || !seen[fieldDepth] {
		t.Fatalf("visited %d fields, want all %d including Hit Rate and Depth", len(seen), fieldCount)
	}
}

func TestFormSpaceTogglesFocusedToggle(t *testing.T) {
	for _, field := range []int{fieldSimulate, fieldForce, fieldRecursive, fieldNoAbort} {
		m := newFormModel(savedConfig{})
		m.focus = field
		m, _ = m.Update(keySpace)
		for i, on := range m.toggles {
			if on != (i == field) {
				t.Fatalf("space on field %d: toggles = %v, want only it on", field, m.toggles)
			}
		}
		m, _ = m.Update(keySpace)
		if m.toggles[field] {
			t.Fatalf("second space on field %d did not toggle back", field)
		}
	}

	// On a text field, space is typed rather than toggling anything.
	m := newFormModel(savedConfig{})
	m.focus = fieldExclude
	m.inputs[fieldExclude].Focus()
	m, _ = m.Update(typeText("a"))
	m, _ = m.Update(keySpace)
	if m.inputs[fieldExclude].Value() != "a " || m.toggles != [fieldCount]bool{} {
		t.Fatalf("space in a text field: value=%q toggles=%v", m.inputs[fieldExclude].Value(), m.toggles)
	}
}

func TestFormTypingAndResize(t *testing.T) {
	m := newFormModel(savedConfig{})
	m, _ = m.Update(typeText("example.com"))
	if got := m.inputs[fieldDomain].Value(); got != "example.com" {
		t.Fatalf("domain = %q", got)
	}
	m, _ = m.Update(tea.WindowSizeMsg{Width: 90, Height: 30})
	if m.width != 90 {
		t.Fatalf("width = %d", m.width)
	}
	// Keys on a toggle are not forwarded to any input.
	m.focus = fieldForce
	m, _ = m.Update(typeText("x"))
	if m.inputs[fieldDomain].Value() != "example.com" {
		t.Fatalf("typing on a toggle changed the domain: %q", m.inputs[fieldDomain].Value())
	}
}

func TestFormViewShowsFocusHintsAndGates(t *testing.T) {
	m := newFormModel(savedConfig{})
	v := m.View()
	for _, want := range []string{"Configure Scan", "▸ ", "(enable Simulate)", "(enable Recursive)", "ctrl+r run"} {
		if !strings.Contains(v, want) {
			t.Errorf("form view lacks %q", want)
		}
	}
	m.focus = fieldRecursive
	m.toggles[fieldSimulate], m.toggles[fieldRecursive] = true, true
	v = m.View()
	if !strings.Contains(v, "[space to toggle]") || strings.Contains(v, "(enable Simulate)") || strings.Contains(v, "(enable Recursive)") {
		t.Errorf("view with simulate and recursive on:\n%s", v)
	}
	m.err = "Domain is required"
	if !strings.Contains(m.View(), "✗ Domain is required") {
		t.Error("form view does not show the error")
	}
}

func TestModelFormKeys(t *testing.T) {
	m := Model{state: stateForm, form: newFormModel(savedConfig{})}
	if m.Init() == nil {
		t.Error("Init returned no blink command")
	}
	if !strings.Contains(m.View().Content, "Configure Scan") {
		t.Error("model view is not the form")
	}

	// ctrl+r with an invalid domain shows an error and starts nothing.
	m.form.inputs[fieldDomain].SetValue("not a domain!")
	next, cmd := m.Update(keyCtrlR)
	nm := next.(Model)
	if cmd != nil || nm.form.err == "" || nm.form.loading || nm.state != stateForm {
		t.Fatalf("invalid domain: cmd=%v err=%q loading=%v state=%v", cmd != nil, nm.form.err, nm.form.loading, nm.state)
	}

	// A resize reaches both the model and the form.
	next, _ = nm.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	nm = next.(Model)
	if nm.width != 100 || nm.height != 40 || nm.form.width != 100 {
		t.Fatalf("resize: model %dx%d form %d", nm.width, nm.height, nm.form.width)
	}

	// Keys reach the focused form field.
	next, _ = nm.Update(keyTab)
	if next.(Model).form.focus != fieldWordlist {
		t.Fatalf("tab through the model: focus=%d", next.(Model).form.focus)
	}

	_, cmd = nm.Update(keyCtrlC)
	if cmd == nil {
		t.Fatal("ctrl+c on the form returned no command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("ctrl+c on the form did not quit")
	}
}

func TestModelScanKeys(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := Model{state: stateScan, scanView: newScanViewModel(80, 24, false), cancel: cancel}
	if m.View().Content == "" {
		t.Fatal("scan state renders nothing")
	}

	// q and r do nothing while the scan runs.
	for _, k := range []tea.KeyPressMsg{typeText("q"), typeText("r")} {
		next, cmd := m.Update(k)
		if next.(Model).state != stateScan {
			t.Fatalf("%q during a scan left the scan screen", k.String())
		}
		if cmd != nil {
			if _, quit := cmd().(tea.QuitMsg); quit {
				t.Fatalf("%q during a scan quit", k.String())
			}
		}
	}

	// ctrl+c during a scan cancels it and marks it aborted, without quitting.
	next, _ := m.Update(keyCtrlC)
	am := next.(Model)
	if ctx.Err() == nil || !am.scanView.aborted || am.state != stateScan {
		t.Fatalf("ctrl+c during a scan: cancelled=%v aborted=%v state=%v", ctx.Err() != nil, am.scanView.aborted, am.state)
	}

	// Once done, q quits and r returns to a fresh form.
	am.scanView.done = true
	if _, cmd := am.Update(typeText("q")); cmd == nil {
		t.Fatal("q after done returned no command")
	} else if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("q after done did not quit")
	}
	redirectConfig(t)
	next, cmd := am.Update(typeText("r"))
	fm := next.(Model)
	if fm.state != stateForm || fm.events != nil || cmd == nil {
		t.Fatalf("r after done: state=%v events=%v cmd=%v", fm.state, fm.events != nil, cmd != nil)
	}
	if !strings.Contains(fm.View().Content, "Configure Scan") {
		t.Fatal("r after done does not show the form")
	}
}
