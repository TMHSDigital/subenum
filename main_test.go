package main

import (
	"testing"
)

func TestResolveAttempts(t *testing.T) {
	got, err := resolveAttempts(0, 0)
	if err != nil || got != 1 {
		t.Errorf("default: got %d, err %v; want 1, nil", got, err)
	}
	got, err = resolveAttempts(5, 0)
	if err != nil || got != 5 {
		t.Errorf("-attempts=5: got %d, err %v; want 5, nil", got, err)
	}
	got, err = resolveAttempts(0, 3)
	if err != nil || got != 3 {
		t.Errorf("-retries=3: got %d, err %v; want 3, nil", got, err)
	}
	_, err = resolveAttempts(5, 3)
	if err == nil {
		t.Error("both set: expected error, got nil")
	}
}

func TestFormatVersion(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })

	Version = "0.7.0"
	if got := formatVersion(); got != "subenum v0.7.0" {
		t.Errorf("fallback: got %q", got)
	}
	Version = "v0.7.0"
	if got := formatVersion(); got != "subenum v0.7.0" {
		t.Errorf("git describe tag: got %q", got)
	}
}
