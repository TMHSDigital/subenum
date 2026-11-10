package main

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestE2EMultipleWordlists covers #199: -w repeats, the files are combined
// and an entry found in both is scanned once.
func TestE2EMultipleWordlists(t *testing.T) {
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
