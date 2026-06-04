package tui

import (
	"strings"
	"testing"
)

func TestNewFormModelDefaults(t *testing.T) {
	m := newFormModel(savedConfig{})
	if len(m.inputs) != 7 {
		t.Fatalf("expected 7 text inputs, got %d", len(m.inputs))
	}
	if m.focus != fieldDomain {
		t.Errorf("expected initial focus on domain, got %d", m.focus)
	}
	if got := m.inputs[1].Value(); got != "examples/sample_wordlist.txt" {
		t.Errorf("default wordlist = %q", got)
	}
	if got := m.inputs[4].Value(); got != "100" {
		t.Errorf("default concurrency = %q", got)
	}
}

func TestValidateMissingDomain(t *testing.T) {
	m := newFormModel(savedConfig{})
	m.inputs[0].SetValue("")
	if _, errStr := m.validate(); errStr == "" {
		t.Error("expected validation error for missing domain")
	}
}

func TestValidateNonPositiveConcurrency(t *testing.T) {
	m := newFormModel(savedConfig{})
	m.inputs[0].SetValue("example.com")
	m.inputs[4].SetValue("0")
	_, errStr := m.validate()
	if !strings.Contains(errStr, "Concurrency") {
		t.Errorf("expected concurrency error, got %q", errStr)
	}
}

// Empty hit rate must be accepted when Simulate is OFF (it is never used),
// and rejected when Simulate is ON.
func TestValidateHitRateOnlyWhenSimulate(t *testing.T) {
	live := newFormModel(savedConfig{})
	live.inputs[0].SetValue("example.com")
	live.inputs[2].SetValue("") // blank hit rate
	live.toggles[0] = false
	vals, errStr := live.validate()
	if errStr != "" {
		t.Errorf("live mode should ignore hit rate, got error %q", errStr)
	}
	if vals.hitRate < 1 || vals.hitRate > 100 {
		t.Errorf("live mode should set a sane default hit rate, got %d", vals.hitRate)
	}

	sim := newFormModel(savedConfig{})
	sim.inputs[0].SetValue("example.com")
	sim.inputs[2].SetValue("") // blank hit rate
	sim.toggles[0] = true
	if _, errStr := sim.validate(); errStr == "" {
		t.Error("simulate mode should reject blank hit rate")
	}

	sim.inputs[2].SetValue("500") // out of range
	if _, errStr := sim.validate(); errStr == "" {
		t.Error("simulate mode should reject out-of-range hit rate")
	}
}
