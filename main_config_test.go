package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain keeps every test in this package hermetic: no developer config
// file or SUBENUM_* variable can change flag defaults (#88).
func TestMain(m *testing.M) {
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "SUBENUM_") {
			_ = os.Unsetenv(name)
		}
	}
	_ = os.Setenv(configEnv, filepath.Join(os.TempDir(), "subenum-test-no-such-config.json"))
	// An interrupted run saves resume state; keep it out of the package dir.
	_ = os.Setenv("SUBENUM_STATE", filepath.Join(os.TempDir(), "subenum-test-resume.json"))
	os.Exit(m.Run())
}

// TestDefaultsPrecedence covers #88: flag > environment > config file >
// built-in default, for each kind of flag.
func TestDefaultsPrecedence(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfg, []byte(`{"dns-server": "1.1.1.1:53", "rate": 1000000, "t": 10, "force": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"SUBENUM_RATE": "300", "SUBENUM_T": "20"}
	d := &defaultsLoader{path: cfg, getenv: func(k string) string { return env[k] }}

	f, _, fs, err := parseFlagsWith([]string{"-t", "30", "example.com"}, d.apply)
	if err != nil {
		t.Fatal(err)
	}
	if f.dnsServer != "1.1.1.1:53" || !f.force {
		t.Errorf("config not applied: dns-server %q, force %v", f.dnsServer, f.force)
	}
	if f.rate != 300 {
		t.Errorf("rate = %d, want 300 (env beats config)", f.rate)
	}
	if f.concurrency != 30 {
		t.Errorf("t = %d, want 30 (flag beats env and config)", f.concurrency)
	}
	if f.timeoutMs != 1000 {
		t.Errorf("timeout = %d, want the built-in 1000", f.timeoutMs)
	}

	var out bytes.Buffer
	d.printConfig(&out, fs)
	for _, want := range []string{`dns-server     = "1.1.1.1:53"`, "(config)", `rate           = "300"`, "(env)", `t              = "30"`, "(flag)", `timeout        = "1000"`, "(default)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("-print-config lacks %q:\n%s", want, out.String())
		}
	}

	// A config value no longer counts as "given on the command line", so
	// explicit-only checks (such as -progress on a non-terminal) still work.
	given := false
	fs.Visit(func(fl *flag.Flag) { given = given || fl.Name == "dns-server" })
	if given {
		t.Error("a config-file value was marked as an explicit flag")
	}
}

func TestDefaultsErrors(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"unknown key": `{"no-such-flag": 1}`,
		"bad value":   `{"t": "many"}`,
		"mode flag":   `{"tui": true}`,
		"not json":    `dns-server = "1.1.1.1"`,
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		d := &defaultsLoader{path: path, getenv: func(string) string { return "" }}
		if _, _, _, err := parseFlagsWith(nil, d.apply); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	d := &defaultsLoader{getenv: func(k string) string {
		if k == "SUBENUM_RATE" {
			return "fast"
		}
		return ""
	}}
	if _, _, _, err := parseFlagsWith(nil, d.apply); err == nil || !strings.Contains(err.Error(), "SUBENUM_RATE") {
		t.Errorf("bad env value: err = %v", err)
	}
}

func TestE2EConfigErrorExits2(t *testing.T) {
	cfg := writeFile(t, "config.json", `{"no-such-flag": true}`)
	t.Setenv(configEnv, cfg)
	if code, out := runCLIMerged(t, "-simulate", "example.com"); code != 2 || !strings.Contains(out, "no-such-flag") {
		t.Fatalf("exit %d, output %q", code, out)
	}
}

// TestGeneratedDocsCoverEveryFlag covers #88: each completion script and the
// man page mention every flag.
func TestGeneratedDocsCoverEveryFlag(t *testing.T) {
	outputs := map[string]string{}
	for shell := range completionFiles {
		var b bytes.Buffer
		if err := writeCompletion(&b, shell); err != nil {
			t.Fatal(err)
		}
		outputs[shell] = b.String()
	}
	var man bytes.Buffer
	writeManPage(&man)
	outputs["man"] = man.String()

	for _, f := range flagInfos() {
		for kind, text := range outputs {
			want := "-" + f.name
			switch kind {
			case "fish":
				want = "-o " + f.name
			case "man":
				want = `\-` + strings.ReplaceAll(f.name, "-", `\-`)
			}
			if !strings.Contains(text, want) {
				t.Errorf("%s output does not mention flag %s", kind, f.name)
			}
		}
	}
	if code, _ := runSubcommand([]string{"completion", "tcsh"}, &bytes.Buffer{}, &bytes.Buffer{}); code != exitUsage {
		t.Errorf("unknown shell: exit %d, want 2", code)
	}
}

// TestDefaultsValueTypes covers #116: only scalars are settings, list flags
// also take a JSON array, and mode flags are refused by name.
func TestDefaultsValueTypes(t *testing.T) {
	dir := t.TempDir()
	load := func(content string) (cliFlags, error) {
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		d := &defaultsLoader{path: path, getenv: func(string) string { return "" }}
		f, _, _, err := parseFlagsWith(nil, d.apply)
		return f, err
	}
	for _, bad := range []string{`{"format": null}`, `{"t": {"n": 1}}`, `{"t": [1]}`, `{"exclude": [1]}`} {
		if _, err := load(bad); err == nil || !strings.Contains(err.Error(), "must be") {
			t.Errorf("%s: err = %v, want a type error", bad, err)
		}
	}
	for _, mode := range []string{`{"resume": "state.json"}`, `{"tui": true}`} {
		if _, err := load(mode); err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("%s: err = %v, want \"not allowed\"", mode, err)
		}
	}
	f, err := load(`{"exclude": ["a.example.com", "*.b.example.com"], "type": ["A", "CNAME"]}`)
	if err != nil || f.exclude != "a.example.com,*.b.example.com" || f.recordTypes != "A,CNAME" {
		t.Errorf("list values: exclude %q, type %q, err %v", f.exclude, f.recordTypes, err)
	}
	// Every bad value is reported, not just the first.
	if _, err := load(`{"t": "many", "rate": "fast"}`); err == nil || !strings.Contains(err.Error(), "many") || !strings.Contains(err.Error(), "fast") {
		t.Errorf("two bad values: err = %v", err)
	}
}

// TestE2EBrokenConfigStillAnswersHelp covers #116: -h, -version and
// -print-config work with a bad SUBENUM_* value; a scan still refuses.
func TestE2EBrokenConfigStillAnswersHelp(t *testing.T) {
	t.Setenv("SUBENUM_T", "abc")
	for _, args := range [][]string{{"-h"}, {"-version"}, {"-print-config"}} {
		if code, out := runCLIMerged(t, args...); code != exitOK {
			t.Errorf("%v: exit %d, want 0\n%s", args, code, out)
		}
	}
	if code, out := runCLIMerged(t, "-simulate", "example.com"); code != exitUsage || !strings.Contains(out, "SUBENUM_T") {
		t.Errorf("scan with a bad env value: exit %d\n%s", code, out)
	}
}

// TestE2EAttemptsPrecedence covers #116: an explicit flag beats a config or
// env value of the other spelling instead of conflicting with it.
func TestE2EAttemptsPrecedence(t *testing.T) {
	wl := writeFile(t, "wl.txt", "www\n")
	t.Setenv(configEnv, writeFile(t, "config.json", `{"attempts": 3}`))
	if code, out := runCLIMerged(t, "-simulate", "-retries", "2", "-w", wl, "example.com"); code != exitOK {
		t.Errorf("config attempts + -retries: exit %d\n%s", code, out)
	}
	t.Setenv("SUBENUM_RETRIES", "2")
	if code, out := runCLIMerged(t, "-simulate", "-attempts", "2", "-w", wl, "example.com"); code != exitOK {
		t.Errorf("SUBENUM_RETRIES + -attempts: exit %d\n%s", code, out)
	}
}
