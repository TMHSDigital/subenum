package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestE2EMultipleWordlists covers #199: -w repeats, the files are combined
// and an entry found in both is scanned once.
func TestE2EMultipleWordlists(t *testing.T) {
	t.Parallel()
	general := writeFile(t, "general.txt", "www\nmail\napi\n")
	specific := writeFile(t, "specific.txt", "# target-specific\napi\nstaging\nWWW\n")
	code, out := runCLI(t, "", "-simulate", "-hit-rate", "100", "-progress=false", "-w", general, "-w", specific, "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Fields(out)
	sort.Strings(lines)
	want := "api.example.com,mail.example.com,staging.example.com,www.example.com"
	if got := strings.Join(lines, ","); got != want {
		t.Errorf("results = %q, want %q", got, want)
	}
}

// TestE2EMultipleWordlistsWithStdin: "-" stays valid as one of the entries.
func TestE2EMultipleWordlistsWithStdin(t *testing.T) {
	t.Parallel()
	file := writeFile(t, "wl.txt", "www\n")
	code, out := runCLI(t, "mail\nwww\n", "-simulate", "-hit-rate", "100", "-progress=false", "-w", file, "-w", "-", "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Fields(out)
	sort.Strings(lines)
	if got := strings.Join(lines, ","); got != "mail.example.com,www.example.com" {
		t.Errorf("results = %q", got)
	}
}

func TestMultipleWordlistsRejectedInputs(t *testing.T) {
	file := writeFile(t, "wl.txt", "www\n")
	for name, args := range map[string][]string{
		"stdin twice":      {"-w", "-", "-w", "-", "example.com"},
		"stdin with -dL -": {"-w", file, "-w", "-", "-dL", "-"},
		"one file missing": {"-w", file, "-w", filepath.Join(t.TempDir(), "nope.txt"), "example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _ := runCLI(t, "", append([]string{"-simulate", "-progress=false"}, args...)...)
			if code == 0 {
				t.Errorf("exit 0, want a failure")
			}
		})
	}
}

// runCLIStderr runs the CLI with stdin and returns the exit code and stderr.
func runCLIStderr(t *testing.T, stdin string, args ...string) (int, string) {
	t.Helper()
	var stderr bytes.Buffer
	code := runWith(runArgs{args: args, stdin: strings.NewReader(stdin), stdout: io.Discard, stderr: &stderr})
	return code, stderr.String()
}

// TestStdinReadOnce covers #378: every flag that takes "-" is counted, so a
// second reader is refused up front instead of failing on an empty input.
func TestStdinReadOnce(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"-exclude-file and -w":        {[]string{"-exclude-file", "-", "-w", "-", "example.com"}, "-w, -exclude-file cannot all read standard input"},
		"-r and -w":                   {[]string{"-r", "-", "-w", "-", "example.com"}, "-w, -r cannot all read standard input"},
		"-takeover-providers and -dL": {[]string{"-takeover-providers", "-", "-dL", "-"}, "-dL, -takeover-providers cannot all read standard input"},
		"-w and -dL":                  {[]string{"-w", "-", "-dL", "-"}, "-w, -dL cannot all read standard input"},
		"-w twice":                    {[]string{"-w", "-", "-w", "-", "example.com"}, "-w - is given 2 times"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			code, stderr := runCLIStderr(t, "www\napi\n", append([]string{"-simulate", "-progress=false"}, tc.args...)...)
			if code != exitUsage || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit %d, stderr %q; want exit %d and %q", code, stderr, exitUsage, tc.want)
			}
		})
	}
	// One reader of stdin is still fine.
	excl := writeFile(t, "excl.txt", "api.example.com\n")
	code, stderr := runCLIStderr(t, "www\napi\n", "-simulate", "-hit-rate", "100", "-progress=false", "-exclude-file", excl, "-w", "-", "example.com")
	if code != exitOK {
		t.Errorf("one stdin reader: exit %d, stderr %q", code, stderr)
	}
}

// TestOutputFilesSameFile covers #378: one file spelled two ways, or named
// by -o and by -stats, -sarif or -inconclusive, is refused rather than
// written twice with only the last one kept.
func TestOutputFilesSameFile(t *testing.T) {
	t.Parallel()
	words := writeFile(t, "words.txt", "www\n")
	dir := t.TempDir()
	rel := filepath.Join(dir, "sub", "..", "r.txt")
	abs := filepath.Join(dir, "r.txt")
	cases := map[string][]string{
		"-o twice, spelled differently": {"-o", "text:" + rel, "-o", "jsonl:" + abs},
		"-o and -stats":                 {"-o", abs, "-stats", rel},
		"-o and -sarif":                 {"-o", abs, "-sarif", abs},
		"-stats and -inconclusive":      {"-stats", abs, "-inconclusive", rel},
		"-state and -o":                 {"-state", abs, "-o", "text:" + rel},
		"-state and -stats":             {"-state", abs, "-stats", rel},
		"-state and -diff":              {"-state", abs, "-diff", rel},
		"-diff and -stats":              {"-diff", abs, "-stats", rel},
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		cases["-o twice, another case"] = []string{"-o", abs, "-o", "jsonl:" + strings.ToUpper(abs)}
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			code, stderr := runCLIStderr(t, "", append(append([]string{"-simulate", "-progress=false", "-w", words}, args...), "example.com")...)
			if code != exitUsage || !strings.Contains(stderr, "name the same file") {
				t.Errorf("exit %d, stderr %q; want exit %d and \"name the same file\"", code, stderr, exitUsage)
			}
		})
	}
}

// TestWordlistDefaultsReplaced: a config-file or SUBENUM_W wordlist is a
// default, so a later source replaces it instead of adding to it.
func TestWordlistDefaultsReplaced(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfg, []byte(`{"w": "from-config.txt"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  map[string]string
		args []string
		want []string
	}{
		{"config only", nil, nil, []string{"from-config.txt"}},
		{"env beats config", map[string]string{"SUBENUM_W": "from-env.txt"}, nil, []string{"from-env.txt"}},
		{"flags beat env and config", map[string]string{"SUBENUM_W": "from-env.txt"}, []string{"-w", "a.txt", "-w", "b.txt"}, []string{"a.txt", "b.txt"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &defaultsLoader{path: cfg, getenv: func(k string) string { return tc.env[k] }}
			f, _, _, err := parseFlagsWith(append(tc.args, "example.com"), d.apply, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(f.wordlists.paths, tc.want) {
				t.Errorf("wordlists = %q, want %q", f.wordlists.paths, tc.want)
			}
		})
	}
}

func TestParseFlagsRepeatedWordlist(t *testing.T) {
	f, _, fs, err := parseFlags([]string{"-w", "a.txt", "example.com", "-w", "b.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.txt", "b.txt"}; !slices.Equal(f.wordlists.paths, want) {
		t.Errorf("wordlists = %q, want %q", f.wordlists.paths, want)
	}
	if got := fs.Lookup("w").Value.String(); got != "a.txt,b.txt" {
		t.Errorf("-w value = %q", got)
	}
	f, _, _, err = parseFlags([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.wordlists.paths) != 0 {
		t.Errorf("no -w: wordlists = %q, want none (bundled list)", f.wordlists.paths)
	}
}
