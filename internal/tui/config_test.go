package tui

import (
	"os"
	"path/filepath"
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

// filledForm returns a form with every toggle ON and every text field set to
// a value that is not its default and that validate keeps as typed, so a saved
// and reloaded form shows it unchanged. A new text field needs a value here.
func filledForm(t *testing.T) formModel {
	t.Helper()
	texts := map[int]string{
		fieldDomain: "example.com", fieldWordlist: "words.txt", fieldSources: "ct,wayback",
		fieldHitRate: "40", fieldDNSServer: "192.0.2.53:53", fieldResolvers: "pool.txt",
		fieldRatePerResolver: "5", fieldConcurrency: "7", fieldTimeout: "700", fieldAttempts: "2",
		fieldTypes: "A,CNAME", fieldDepth: "3", fieldRate: "50", fieldMaxQueries: "10",
		fieldMaxDuration: "1h30m0s", fieldExclude: "vpn.example.com,*.corp.example.com",
		fieldOutput: "out.json", fieldFormat: "json", fieldStats: "run.json",
	}
	m := newFormModel(savedConfig{})
	for f, spec := range formFields {
		if spec.kind == toggleField {
			m.toggles[f] = true
			continue
		}
		v, ok := texts[f]
		if !ok {
			t.Fatalf("no test value for the %s field; add one to filledForm", spec.name())
		}
		if v == m.inputs[f].Value() {
			t.Fatalf("the test value for the %s field is its default, %q", spec.name(), v)
		}
		m.inputs[f].SetValue(v)
	}
	return m
}

// savedJSON validates the form, saves it and returns last.json as written.
func savedJSON(t *testing.T, m formModel) string {
	t.Helper()
	vals, errStr := m.validate()
	if errStr != "" {
		t.Fatalf("validate: %s", errStr)
	}
	if err := saveConfig(vals.saved); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	p, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestSaveLoadConfigRoundTrip covers #307: every form row, set to something
// other than its default, survives validate, saveConfig, loadSavedConfig and a
// new form. A field that is not remembered fails here.
func TestSaveLoadConfigRoundTrip(t *testing.T) {
	redirectConfig(t)

	m := filledForm(t)
	savedJSON(t, m)
	sc, ok := loadSavedConfig()
	if !ok {
		t.Fatal("loadSavedConfig returned ok=false after saveConfig")
	}
	again := newFormModel(sc)
	for f, spec := range formFields {
		if got, want := again.inputs[f].Value(), m.inputs[f].Value(); got != want {
			t.Errorf("%s came back as %q, want %q", spec.name(), got, want)
		}
		if again.toggles[f] != m.toggles[f] {
			t.Errorf("%s came back %v, want %v", spec.name(), again.toggles[f], m.toggles[f])
		}
	}
}

// TestSavedConfigFile pins last.json byte for byte (#307): the keys and their
// order, and the values as validate normalizes them, with a hidden or blank
// field saved as its default.
func TestSavedConfigFile(t *testing.T) {
	sparse := newFormModel(savedConfig{})
	for f, v := range map[int]string{
		fieldDomain: "https://Example.COM./", fieldSources: "wayback, ct", fieldHitRate: "55", fieldDNSServer: " ",
		fieldConcurrency: " 050 ", fieldTypes: "cname, a", fieldDepth: "4", fieldRate: "",
		fieldMaxDuration: " 20m ", fieldExclude: " vpn.example.com , ,*.corp.example.com", fieldFormat: "",
	} {
		sparse.inputs[f].SetValue(v)
	}
	for name, tc := range map[string]struct {
		form formModel
		want string
	}{
		"every row set": {filledForm(t), `{
  "domain": "example.com",
  "wordlist": "words.txt",
  "dns_server": "192.0.2.53:53",
  "resolvers": "pool.txt",
  "rate_per_resolver": 5,
  "concurrency": 7,
  "timeout_ms": 700,
  "attempts": 2,
  "hit_rate": 40,
  "types": "A,CNAME",
  "depth": 3,
  "rate": 50,
  "max_queries": 10,
  "exclude": "vpn.example.com,*.corp.example.com",
  "output": "out.json",
  "format": "json",
  "simulate": true,
  "force": true,
  "recursive": true,
  "no_abort": true,
  "auto_rate": true,
  "max_duration": "1h30m0s",
  "retry_inconclusive": true,
  "sources": "ct,wayback",
  "permute": true,
  "axfr": true,
  "nsec_walk": true,
  "stats": "run.json"
}`},
		"normalized, hidden and blank rows": {sparse, `{
  "domain": "example.com",
  "wordlist": "",
  "dns_server": "8.8.8.8:53",
  "concurrency": 50,
  "timeout_ms": 1000,
  "attempts": 1,
  "hit_rate": 15,
  "types": "CNAME,A",
  "depth": 1,
  "rate": 0,
  "max_queries": 0,
  "exclude": "vpn.example.com,*.corp.example.com",
  "output": "",
  "format": "text",
  "simulate": false,
  "force": false,
  "recursive": false,
  "no_abort": false,
  "max_duration": "20m0s",
  "sources": "ct,wayback"
}`},
	} {
		t.Run(name, func(t *testing.T) {
			redirectConfig(t)
			if got := savedJSON(t, tc.form); got != tc.want {
				t.Errorf("last.json:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

func TestLoadSavedConfigMissing(t *testing.T) {
	redirectConfig(t)
	if _, ok := loadSavedConfig(); ok {
		t.Error("expected ok=false when no config file exists")
	}
}

func TestLoadSavedConfigCorrupt(t *testing.T) {
	for name, data := range map[string]string{
		"truncated":          `{"domain":`,
		"invalid field type": `{"domain":"saved.example.com","concurrency":"many"}`,
	} {
		t.Run(name, func(t *testing.T) {
			redirectConfig(t)
			p, err := configPath()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if sc, ok := loadSavedConfig(); ok || sc != (savedConfig{}) {
				t.Fatalf("loadSavedConfig = %+v, %v; want empty config, false", sc, ok)
			}
			m := New(Options{})
			if m.state != stateForm {
				t.Fatalf("startup state = %v, want form", m.state)
			}
			defaults := newFormModel(savedConfig{})
			for f, spec := range formFields {
				if got, want := m.form.inputs[f].Value(), defaults.inputs[f].Value(); got != want {
					t.Errorf("%s = %q, want default %q", spec.name(), got, want)
				}
				if m.form.toggles[f] != defaults.toggles[f] {
					t.Errorf("%s = %v, want default %v", spec.name(), m.form.toggles[f], defaults.toggles[f])
				}
			}
		})
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
	if got := m.inputs[fieldDomain].Value(); got != "seed.com" {
		t.Errorf("domain seed = %q", got)
	}
	if got := m.inputs[fieldConcurrency].Value(); got != "321" {
		t.Errorf("concurrency seed = %q", got)
	}
	if got := m.inputs[fieldTypes].Value(); got != "CNAME" {
		t.Errorf("types seed = %q", got)
	}
	if got := m.inputs[fieldDepth].Value(); got != "5" {
		t.Errorf("depth seed = %q", got)
	}
	if got := m.inputs[fieldRate].Value(); got != "7" {
		t.Errorf("rate seed = %q", got)
	}
	if !m.toggles[fieldRecursive] {
		t.Error("recursive toggle should be seeded ON")
	}
}
