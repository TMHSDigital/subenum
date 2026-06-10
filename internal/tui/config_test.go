package tui

import (
	"runtime"
	"testing"
)

// redirectConfig points os.UserConfigDir at a temp directory so config tests do
// not touch the real user config and stay hermetic across platforms.
func redirectConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("AppData", dir)
	case "darwin":
		t.Setenv("HOME", dir)
	default:
		t.Setenv("XDG_CONFIG_HOME", dir)
	}
}

func TestSaveLoadConfigRoundTrip(t *testing.T) {
	redirectConfig(t)

	fv := formValues{
		domain:      "example.com",
		wordlist:    "wl.txt",
		dnsServer:   "1.1.1.1:53",
		concurrency: 200,
		timeoutMs:   500,
		attempts:    3,
		hitRate:     42,
		recordTypes: []string{"A", "CNAME"},
		recursive:   true,
		depth:       4,
		rate:        25,
		outputFile:  "out.json",
		formatName:  "json",
		simulate:    true,
		force:       true,
	}

	if err := saveConfig(fv); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	sc, ok := loadSavedConfig()
	if !ok {
		t.Fatal("loadSavedConfig returned ok=false after saveConfig")
	}

	if sc.Domain != fv.domain || sc.Wordlist != fv.wordlist || sc.DNSServer != fv.dnsServer {
		t.Errorf("string fields did not round-trip: %+v", sc)
	}
	if sc.Concurrency != fv.concurrency || sc.TimeoutMs != fv.timeoutMs || sc.Attempts != fv.attempts {
		t.Errorf("numeric scan fields did not round-trip: %+v", sc)
	}
	if sc.HitRate != fv.hitRate || sc.Depth != fv.depth || sc.Rate != fv.rate {
		t.Errorf("hit-rate/depth/rate did not round-trip: %+v", sc)
	}
	if sc.Types != "A,CNAME" {
		t.Errorf("Types = %q, want %q", sc.Types, "A,CNAME")
	}
	if sc.Output != "out.json" || sc.Format != "json" {
		t.Errorf("output/format did not round-trip: %+v", sc)
	}
	if !sc.Simulate || !sc.Force || !sc.Recursive {
		t.Errorf("toggle fields did not round-trip: %+v", sc)
	}
}

func TestLoadSavedConfigMissing(t *testing.T) {
	redirectConfig(t)
	if _, ok := loadSavedConfig(); ok {
		t.Error("expected ok=false when no config file exists")
	}
}

// TestSavedConfigSeedsForm verifies a saved config drives the form defaults,
// which is what the `r` (new scan) keybind and startup rely on.
func TestSavedConfigSeedsForm(t *testing.T) {
	sc := savedConfig{
		Domain:      "seed.com",
		Wordlist:    "seed.txt",
		Concurrency: 321,
		Types:       "CNAME",
		Depth:       5,
		Rate:        7,
		Recursive:   true,
		Simulate:    true,
	}
	m := newFormModel(sc)
	if got := m.inputs[0].Value(); got != "seed.com" {
		t.Errorf("domain seed = %q", got)
	}
	if got := m.inputs[4].Value(); got != "321" {
		t.Errorf("concurrency seed = %q", got)
	}
	if got := m.inputs[7].Value(); got != "CNAME" {
		t.Errorf("types seed = %q", got)
	}
	if got := m.inputs[8].Value(); got != "5" {
		t.Errorf("depth seed = %q", got)
	}
	if got := m.inputs[9].Value(); got != "7" {
		t.Errorf("rate seed = %q", got)
	}
	if !m.toggles[2] {
		t.Error("recursive toggle should be seeded ON")
	}
}
