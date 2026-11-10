package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
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
		{"-- as a flag value is not a terminator", []string{"-w", "wl.txt", "-o", "--", "example.com", "-t", "5"}, []string{"example.com"}, 5, false},
		{"terminator after a bool flag", []string{"-w", "wl.txt", "-simulate", "--", "-weird.example"}, []string{"-weird.example"}, 100, true},
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
			if got := f.wordlists.paths; len(got) != 1 || got[0] != "wl.txt" {
				t.Errorf("wordlist = %q, want [wl.txt]", got)
			}
		})
	}
}

// TestLoadTargets covers #41: -dL skips comments, invalid and duplicate
// domains, and normalizes case and trailing dots.
func TestLoadTargets(t *testing.T) {
	p := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(p, []byte("# list\nA.example\nb.example.\n\nnot a domain\na.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := output.New(nil, false, output.FormatText)
	got, ok := loadTargets(cliFlags{domainList: p}, &runtimeInputs{}, "", out)
	if !ok || !reflect.DeepEqual(got, []string{"a.example", "b.example"}) {
		t.Fatalf("loadTargets = %q, %v", got, ok)
	}

	if got, ok := loadTargets(cliFlags{}, &runtimeInputs{}, "example.com", out); !ok || !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Fatalf("single domain: %q, %v", got, ok)
	}

	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("# nothing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadTargets(cliFlags{domainList: empty}, &runtimeInputs{}, "", out); ok {
		t.Error("a list with no valid domains should fail")
	}
}

func TestValidateFlagsDomainListConflicts(t *testing.T) {
	base := func() cliFlags {
		f, _, _, err := parseFlags([]string{"-w", "wl.txt"})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	out := output.New(nil, false, output.FormatText)
	_, _, fs, _ := parseFlags(nil)
	fs.SetOutput(io.Discard)

	f := base()
	f.domainList = "d.txt"
	if _, ok := validateFlags(f, &runtimeInputs{maxAttempts: 1}, []string{"example.com"}, fs, out); ok {
		t.Error("domain argument plus -dL should be rejected")
	}
	f.wordlists.paths, f.domainList = []string{"-"}, "-"
	if _, ok := validateFlags(f, &runtimeInputs{maxAttempts: 1}, nil, fs, out); ok {
		t.Error("-w - with -dL - should be rejected")
	}
	f = base()
	f.domainList = "d.txt"
	if d, ok := validateFlags(f, &runtimeInputs{maxAttempts: 1}, nil, fs, out); !ok || d != "" {
		t.Errorf("-dL alone: got %q, %v", d, ok)
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

func TestEffectiveAttempts(t *testing.T) {
	resolve := func(attempts, retries int, aSrc, rSrc string) (int, error) {
		n, _, err := effectiveAttempts(attempts, retries, aSrc, rSrc)
		return n, err
	}
	if _, fromRetries, _ := effectiveAttempts(0, 3, sourceDefault, sourceFlag); !fromRetries {
		t.Error("-retries=3: fromRetries is false, want the deprecation warning")
	}
	d, fl := sourceDefault, sourceFlag
	got, err := resolve(0, 0, d, d)
	if err != nil || got != 1 {
		t.Errorf("default: got %d, err %v; want 1, nil", got, err)
	}
	got, err = resolve(5, 0, fl, d)
	if err != nil || got != 5 {
		t.Errorf("-attempts=5: got %d, err %v; want 5, nil", got, err)
	}
	got, err = resolve(0, 3, d, fl)
	if err != nil || got != 3 {
		t.Errorf("-retries=3: got %d, err %v; want 3, nil", got, err)
	}
	_, err = resolve(5, 3, fl, fl)
	if err == nil {
		t.Error("both set: expected error, got nil")
	}
	// #116: a higher-precedence source wins instead of a conflict.
	for _, c := range []struct {
		attempts, retries int
		aSrc, rSrc        string
		want              int
	}{
		{3, 2, sourceConfig, sourceFlag, 2},
		{2, 2, sourceFlag, sourceEnv, 2},
		{4, 2, sourceEnv, sourceConfig, 4},
	} {
		got, err := resolve(c.attempts, c.retries, c.aSrc, c.rSrc)
		if err != nil || got != c.want {
			t.Errorf("%+v: got %d, err %v; want %d", c, got, err, c.want)
		}
	}
	if _, err := resolve(3, 2, sourceEnv, sourceEnv); err == nil {
		t.Error("both from env: expected error")
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

// TestParseFlagsTUIOnlyAsFlag covers #58: -tui is honoured only as a flag,
// not as another flag's value or an argument after "--".
func TestParseFlagsTUIOnlyAsFlag(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"-tui"}, true},
		{[]string{"-v", "--tui"}, true},
		{[]string{"-o", "-tui", "example.com"}, false},
		{[]string{"-w", "wl.txt", "--", "-tui"}, false},
	} {
		f, _, _, err := parseFlags(tc.args)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if f.tui != tc.want {
			t.Errorf("%v: tui = %v, want %v", tc.args, f.tui, tc.want)
		}
	}
}

// TestAttemptsUsageShowsDefault covers #58: -h shows the effective default.
func TestAttemptsUsageShowsDefault(t *testing.T) {
	_, _, fs, _ := parseFlags(nil)
	if u := fs.Lookup("attempts").Usage; !strings.Contains(u, "default 1") {
		t.Errorf("-attempts usage %q does not show the default", u)
	}
}

// TestCLIBuildsSharedConfig covers #80: the CLI builds the same scan.Config
// as the TUI (see TestFormBuildsSharedConfig) from equivalent inputs.
func TestCLIBuildsSharedConfig(t *testing.T) {
	f, pos, _, err := parseFlags([]string{"-w", "wl.txt", "-t", "50", "-timeout", "800", "-dns-server", "1.1.1.1:53",
		"-simulate", "-hit-rate", "30", "-seed", "7", "-attempts", "2", "-force", "-type", "A,CNAME",
		"-recursive", "-depth", "2", "-rate", "100", "-max-queries", "500", "-no-abort", "example.com"})
	if err != nil || len(pos) != 1 {
		t.Fatalf("parseFlags: %v %v", pos, err)
	}
	types, err := dns.ParseTypes(f.recordTypes)
	if err != nil {
		t.Fatal(err)
	}
	in := &runtimeInputs{maxAttempts: f.attempts, recordTypes: types}
	got := scanOptions(f, in, scanPass{domain: pos[0], entries: []string{"www", "mail"}, maxQueries: f.maxQueries}, nil).Config()
	want := scan.Config{
		Domain: "example.com", Entries: []string{"www", "mail"}, Concurrency: 50,
		Timeout: 800 * time.Millisecond, DNSServer: "1.1.1.1:53", Simulate: true, HitRate: 30,
		Seed: 7, Attempts: 2, Force: true, Types: []string{"A", "CNAME"}, Recursive: true,
		Depth: 2, Rate: 100, MaxQueries: 500, NoAbort: true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CLI config:\n got %+v\nwant %+v", got, want)
	}
}

// TestLoadPrevious covers #84: -diff accepts a previous run in any format.
func TestLoadPrevious(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"text":    "# SIMULATED\nwww.example.com\nMail.Example.com.\n",
		"records": "Found: www.example.com A=192.0.2.1\nmail.example.com A=192.0.2.2 TAKEOVER?=dangling\n",
		"jsonl":   `{"subdomain":"www.example.com","records":[]}` + "\n" + `{"subdomain":"mail.example.com","records":[]}` + "\n" + `{"type":"summary","schema":1}` + "\n",
		"json":    `[{"subdomain":"www.example.com","records":[]},{"subdomain":"mail.example.com","records":[]}]`,
		"csv":     "subdomain,type,value\nwww.example.com,A,192.0.2.1\nwww.example.com,AAAA,2001:db8::1\nmail.example.com,A,192.0.2.2\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadPrevious(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := map[string]struct{}{"www.example.com": {}, "mail.example.com": {}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: names = %v, want www and mail", name, got)
		}
	}
}

// TestE2EMissingDomainReportedFirst covers #120: a missing domain is the
// error a user sees, not a missing -exclude-file, and no simulation banner
// is printed before it.
func TestE2EMissingDomainReportedFirst(t *testing.T) {
	code, out := runCLIMerged(t, "-simulate", "-exclude-file", "no-such-file.txt")
	if code != exitUsage || !strings.Contains(out, "missing <domain>") || strings.Contains(out, "exclude-file:") || strings.Contains(out, "SIMULATION MODE") {
		t.Errorf("exit %d, output:\n%s", code, out)
	}
	if code, out := runCLIMerged(t, "-r", "no-such-resolvers.txt", "example.com"); code != exitFailure {
		t.Errorf("unreadable -r: exit %d, want %d\n%s", code, exitFailure, out)
	}
}

// TestLoadExcludes covers #174: -exclude and -exclude-file merge, blank and
// comment lines add nothing, and an unreadable -exclude-file stops the run
// with exit 1 and the file name, as an unreadable -r or wordlist does.
func TestLoadExcludes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	empty := write("empty.txt", "\n# only comments\n   \n\t# indented\n\n")
	got, err := loadExcludes(cliFlags{excludeFile: empty}, &runtimeInputs{})
	if err != nil || len(got) != 0 {
		t.Errorf("blank and comment lines: %q, %v; want no patterns and no error", got, err)
	}
	mixed := write("mixed.txt", "# dev hosts\n  dev-*  \n\nstaging\n")
	got, err = loadExcludes(cliFlags{exclude: " a , ,b", excludeFile: mixed}, &runtimeInputs{})
	if want := []string{"a", "b", "dev-*", "staging"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("merged: %q, %v; want %q", got, err, want)
	}
	stdin := &runtimeInputs{stdin: strings.NewReader("www\n#x\n")}
	if got, err := loadExcludes(cliFlags{excludeFile: "-"}, stdin); err != nil || !reflect.DeepEqual(got, []string{"www"}) {
		t.Errorf("stdin: %q, %v; want [www]", got, err)
	}

	missing := filepath.Join(dir, "no-such-excludes.txt")
	if _, err := loadExcludes(cliFlags{excludeFile: missing}, &runtimeInputs{}); err == nil {
		t.Error("missing -exclude-file: no error")
	}
	code, out := runCLIMerged(t, "-simulate", "-exclude-file", missing, "example.com")
	if code != exitFailure || !strings.Contains(out, "-exclude-file") || !strings.Contains(out, "no-such-excludes.txt") {
		t.Errorf("missing -exclude-file: exit %d, want %d naming the file\n%s", code, exitFailure, out)
	}
}

// TestTUIOptionsFromFlags covers #195: flags given with -tui pre-fill the
// form over SUBENUM_* values, the domain argument fills the Domain field, and
// what the form cannot take is named in a warning.
func TestTUIOptionsFromFlags(t *testing.T) {
	env := map[string]string{"SUBENUM_RATE": "300", "SUBENUM_T": "20"}
	d := &defaultsLoader{path: filepath.Join(t.TempDir(), "none.json"), getenv: func(k string) string { return env[k] }}
	f, pos, fs, err := parseFlagsWith([]string{"-tui", "-w", "big.txt", "-w", "extra.txt", "-r", "resolvers.txt",
		"-rate-per-resolver", "5", "-t", "30", "-stats", "r.json", "example.com", "other.com"}, d.apply, nil)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	opts := tuiOptions(f, fs, pos, d, &stderr)
	if opts.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", opts.Domain)
	}
	want := map[string]string{"w": "big.txt", "r": "resolvers.txt", "rate-per-resolver": "5", "t": "30", "rate": "300"}
	if !reflect.DeepEqual(opts.Settings, want) {
		t.Errorf("Settings = %v, want %v", opts.Settings, want)
	}
	for _, w := range []string{"using big.txt", "-stats other.com; ignored"} {
		if !strings.Contains(stderr.String(), w) {
			t.Errorf("stderr lacks %q:\n%s", w, stderr.String())
		}
	}

	// A bare -tui warns about nothing.
	f, pos, fs, _ = parseFlagsWith([]string{"-tui"}, d.apply, nil)
	stderr.Reset()
	if opts := tuiOptions(f, fs, pos, d, &stderr); opts.Domain != "" || stderr.Len() != 0 {
		t.Errorf("bare -tui: Domain %q, stderr %q", opts.Domain, stderr.String())
	}
}
