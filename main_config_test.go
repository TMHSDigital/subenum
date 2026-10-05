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
