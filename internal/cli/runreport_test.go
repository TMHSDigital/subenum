package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReportGolden covers #421's golden files: a clean run, a degraded run
// with takeover candidates and a permutation pass over two targets, and a
// run with changes whose lists stop at -limit and count the rest. Set
// UPDATE_GOLDEN=1 to rewrite the want.md files.
func TestReportGolden(t *testing.T) {
	for _, tc := range []struct {
		dir  string
		args []string
	}{
		{"clean", []string{"-results", "results.jsonl"}},
		{"degraded", []string{"-results", "results.jsonl", "-limit", "2"}},
		{"changes", []string{"-changes", "changes.jsonl", "-limit", "2"}},
	} {
		t.Run(tc.dir, func(t *testing.T) {
			dir := filepath.Join("internal", "cli", "testdata", "report", tc.dir)
			args := []string{"report", "-stats", filepath.Join(dir, "run.json")}
			for i := 0; i < len(tc.args); i += 2 {
				args = append(args, tc.args[i], tc.args[i+1])
				if strings.HasSuffix(tc.args[i+1], ".jsonl") {
					args[len(args)-1] = filepath.Join(dir, tc.args[i+1])
				}
			}
			var stdout, stderr bytes.Buffer
			if code := runWith(runArgs{args: args, stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr}); code != exitOK {
				t.Fatalf("exit %d: %s", code, stderr.String())
			}
			golden := filepath.Join(dir, "want.md")
			if os.Getenv("UPDATE_GOLDEN") != "" {
				if err := os.WriteFile(golden, stdout.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got := stdout.String(); got != strings.ReplaceAll(string(want), "\r\n", "\n") {
				t.Errorf("report differs from %s:\n%s", golden, got)
			}
		})
	}
}

// TestReportErrors covers #421: a missing or wrong -stats file and bad
// arguments fail with a message, and nothing is written to stdout.
func TestReportErrors(t *testing.T) {
	results := filepath.Join("internal", "cli", "testdata", "report", "clean", "results.jsonl")
	stats := filepath.Join("internal", "cli", "testdata", "report", "clean", "run.json")
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"report"}, exitUsage, "Usage: subenum report"},
		{[]string{"report", "-stats", stats, "-limit", "0"}, exitUsage, "Usage: subenum report"},
		{[]string{"report", "-stats", stats, "extra"}, exitUsage, "Usage: subenum report"},
		{[]string{"report", "-stats", filepath.Join(t.TempDir(), "missing.json")}, exitFailure, "reading -stats file"},
		{[]string{"report", "-stats", results}, exitFailure, "reading -stats file"},
		{[]string{"report", "-stats", stats, "-changes", stats + ".missing"}, exitFailure, "reading -changes file"},
	} {
		var stdout, stderr bytes.Buffer
		code := runWith(runArgs{args: tc.args, stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr})
		if code != tc.code || !strings.Contains(stderr.String(), tc.want) || stdout.Len() != 0 {
			t.Errorf("%v: exit %d, stderr %q, stdout %q; want exit %d and %q", tc.args, code, stderr.String(), stdout.String(), tc.code, tc.want)
		}
	}
}
