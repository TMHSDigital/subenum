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
