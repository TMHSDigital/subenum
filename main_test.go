package main

import (
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
			if f.wordlistFile != "wl.txt" {
				t.Errorf("wordlist = %q, want wl.txt", f.wordlistFile)
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
	got, ok := loadTargets(cliFlags{domainList: p}, "", out)
	if !ok || !reflect.DeepEqual(got, []string{"a.example", "b.example"}) {
		t.Fatalf("loadTargets = %q, %v", got, ok)
	}

	if got, ok := loadTargets(cliFlags{}, "example.com", out); !ok || !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Fatalf("single domain: %q, %v", got, ok)
	}

	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("# nothing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadTargets(cliFlags{domainList: empty}, "", out); ok {
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
	if _, ok := validateFlags(f, []string{"example.com"}, fs, out, 1); ok {
		t.Error("domain argument plus -dL should be rejected")
	}
	f.wordlistFile, f.domainList = "-", "-"
	if _, ok := validateFlags(f, nil, fs, out, 1); ok {
		t.Error("-w - with -dL - should be rejected")
	}
	f = base()
	f.domainList = "d.txt"
	if d, ok := validateFlags(f, nil, fs, out, 1); !ok || d != "" {
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
	got := scanOptions(f, pos[0], []string{"www", "mail"}, f.attempts, types, nil).Config()
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
