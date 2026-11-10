package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/tui"
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

	f, _, fs, err := parseFlagsWith([]string{"-t", "30", "example.com"}, d.apply, nil)
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
	for _, want := range []string{`dns-server     = "1.1.1.1:53"`, "(config)", `rate           = "300"`, "(env)", `t              = "30"`, "(flag)", `timeout        = "1000"`, "(default)",
		`attempts       = "1"`} { // the effective value, not the flag's unset 0 (#153)
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
		if _, _, _, err := parseFlagsWith(nil, d.apply, nil); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	d := &defaultsLoader{getenv: func(k string) string {
		if k == "SUBENUM_RATE" {
			return "fast"
		}
		return ""
	}}
	if _, _, _, err := parseFlagsWith(nil, d.apply, nil); err == nil || !strings.Contains(err.Error(), "SUBENUM_RATE") {
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
		f, _, _, err := parseFlagsWith(nil, d.apply, nil)
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

// TestFileFlagsAreComplete covers #117: every flag that takes a path is in
// fileFlags, so shells complete file names for it. A new flag whose usage
// mentions a file fails here until it is added.
func TestFileFlagsAreComplete(t *testing.T) {
	for _, f := range flagInfos() {
		if strings.Contains(strings.ToLower(f.usage), "file") && !f.isBool && !fileFlags[f.name] {
			t.Errorf("-%s takes a path (%q) but is not in fileFlags", f.name, f.usage)
		}
	}
	for name := range fileFlags {
		if !slices.ContainsFunc(flagInfos(), func(f flagInfo) bool { return f.name == name }) {
			t.Errorf("fileFlags lists -%s, which is not a flag", name)
		}
	}
}

// -print-config shows the attempts value a scan will use, not the raw 0
// sentinel (#153).
func TestPrintConfigEffectiveAttempts(t *testing.T) {
	for _, tc := range []struct {
		args []string
		env  map[string]string
		want string
	}{
		{nil, nil, `attempts       = "1"                      (default)`},
		{[]string{"-attempts", "4"}, nil, `attempts       = "4"                      (flag)`},
		{[]string{"-retries", "3"}, nil, `attempts       = "3"                      (flag, from retries)`},
		{nil, map[string]string{"SUBENUM_RETRIES": "2"}, `attempts       = "2"                      (env, from retries)`},
		{[]string{"-attempts", "5"}, map[string]string{"SUBENUM_RETRIES": "2"}, `attempts       = "5"                      (flag)`},
	} {
		d := &defaultsLoader{getenv: func(k string) string { return tc.env[k] }}
		_, _, fs, err := parseFlagsWith(append(tc.args, "example.com"), d.apply, nil)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		d.printConfig(&out, fs)
		if !strings.Contains(out.String(), tc.want) {
			t.Errorf("%v %v: -print-config lacks %q:\n%s", tc.args, tc.env, tc.want, out.String())
		}
	}
}

// tuiOmittedFlags are flags the TUI form deliberately has no field for: they
// control CLI-only output, input sources, run state or modes the form does not
// offer, so a SUBENUM_* or config file value for them never seeds the form.
var tuiOmittedFlags = map[string]bool{
	"tui": true, "print-config": true, "version": true, "v": true, "progress": true, "silent": true,
	"simulate-zone": true, "retries": true, "show-records": true, "max-duration": true, "stats": true,
	"sarif": true, "exclude-file": true, "permute": true, "ct": true, "seeds": true, "state": true,
	"diff": true, "diff-records": true, "r": true, "dL": true, "seed": true, "resume": true,
	"rate-per-resolver": true, // only applies to -r, which the TUI has no field for
}

// TestSettingNamesAgreeAcrossFrontEnds covers #160: every flag is either wired
// into the TUI form or listed in tuiOmittedFlags, every flag the form reads
// exists, and every engine setting names a real flag. Adding a flag, a form
// field or a setting in one place but not the others fails here.
func TestSettingNamesAgreeAcrossFrontEnds(t *testing.T) {
	_, _, fs, _ := parseFlags(nil)
	wired := map[string]bool{}
	for _, name := range tui.Flags() {
		if wired[name] {
			t.Errorf("TUI reads -%s for two fields", name)
		}
		wired[name] = true
		if fs.Lookup(name) == nil {
			t.Errorf("TUI reads -%s, which is not a flag", name)
		}
		if tuiOmittedFlags[name] {
			t.Errorf("-%s is wired into the TUI and also listed in tuiOmittedFlags", name)
		}
	}
	fs.VisitAll(func(fl *flag.Flag) {
		if !wired[fl.Name] && !tuiOmittedFlags[fl.Name] {
			t.Errorf("-%s is neither wired into the TUI form nor listed in tuiOmittedFlags", fl.Name)
		}
	})
	for name := range tuiOmittedFlags {
		if fs.Lookup(name) == nil {
			t.Errorf("tuiOmittedFlags lists -%s, which is not a flag", name)
		}
	}
	for _, s := range scan.Settings {
		if fs.Lookup(s.Names().Flag) == nil {
			t.Errorf("setting %q names flag %q, which is not a flag", s, s.Names().Flag)
		}
	}
}
