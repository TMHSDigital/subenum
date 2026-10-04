package main

import (
	"io"
	"reflect"
	"testing"
)

func TestParseFlagsInterspersed(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantPos     []string
		wantThreads int
		wantSim     bool
	}{
		{"flags before domain", []string{"-w", "wl.txt", "-t", "5", "example.com"}, []string{"example.com"}, 5, false},
		{"flags after domain", []string{"-w", "wl.txt", "example.com", "-t", "5", "-simulate"}, []string{"example.com"}, 5, true},
		{"flags on both sides", []string{"-simulate", "example.com", "-t", "7", "-w", "wl.txt"}, []string{"example.com"}, 7, true},
		{"stray positionals kept", []string{"-w", "wl.txt", "a.com", "b.com", "-t", "3"}, []string{"a.com", "b.com"}, 3, false},
		{"terminator stops flag parsing", []string{"-w", "wl.txt", "--", "example.com", "-t"}, []string{"example.com", "-t"}, 100, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, pos, _, err := parseFlags(tc.args)
			if err != nil {
				t.Fatalf("parseFlags: %v", err)
			}
			if !reflect.DeepEqual(pos, tc.wantPos) {
				t.Errorf("positionals = %q, want %q", pos, tc.wantPos)
			}
			if f.concurrency != tc.wantThreads {
				t.Errorf("concurrency = %d, want %d", f.concurrency, tc.wantThreads)
			}
			if f.testMode != tc.wantSim {
				t.Errorf("simulate = %v, want %v", f.testMode, tc.wantSim)
			}
			if f.wordlistFile != "wl.txt" {
				t.Errorf("wordlist = %q, want wl.txt", f.wordlistFile)
			}
		})
	}
}

func TestParseFlagsInvalidAfterDomain(t *testing.T) {
	// Previously ignored: an invalid value after the domain must now be parsed
	// (and rejected by validation) rather than silently dropped.
	f, pos, _, err := parseFlags([]string{"-w", "wl.txt", "example.com", "-t", "0"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if f.concurrency != 0 || len(pos) != 1 {
		t.Fatalf("got concurrency %d, positionals %q", f.concurrency, pos)
	}

	_, _, fs, err := parseFlags([]string{"example.com", "-bogus"})
	if err == nil {
		t.Fatal("unknown flag after domain: expected error")
	}
	fs.SetOutput(io.Discard)
}

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

	// No ldflags: fall back to build info. A test binary has no module
	// version, so this must read "dev" rather than a stale hard-coded number.
	Version = ""
	if got := formatVersion(); got != "subenum dev" {
		t.Errorf("no ldflags: got %q, want %q", got, "subenum dev")
	}
}
