package scan

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	msg := "set {max_queries} or {force}; ({concurrency}, {hit_rate}) {unknown} -x"
	if got, want := Render(msg, FlagName), "set -max-queries or -force; (-t, -hit-rate) {unknown} -x"; got != want {
		t.Errorf("Render = %q, want %q", got, want)
	}
	if got := Render("no tokens", FlagName); got != "no tokens" {
		t.Errorf("Render changed a message without tokens: %q", got)
	}
	for _, s := range Settings {
		if FlagName(s) == "" {
			t.Errorf("setting %q has no flag name", s)
		}
	}
}

// TestEngineMessagesUseSettingTokens covers #100: no string literal in the
// engine names a command-line flag, and every token one uses is a Setting.
func TestEngineMessagesUseSettingTokens(t *testing.T) {
	literal := regexp.MustCompile(`"(?:[^"\\\n]|\\.)*"`)
	flag := regexp.MustCompile(`(?:^|[\s("])-(?:t|timeout|attempts|hit-rate|depth|rate|max-queries|exclude|recursive|force|no-abort|dns-server|type)\b`)
	token := regexp.MustCompile(`\{([a-z_]+)\}`)
	known := map[string]bool{}
	for _, s := range Settings {
		known[string(s)] = true
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		// settings.go is where the CLI's flag names live (FlagName).
		if strings.HasSuffix(f, "_test.go") || f == "settings.go" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, lit := range literal.FindAllString(string(data), -1) {
			if flag.MatchString(lit) {
				t.Errorf("%s: message names a flag: %s", f, lit)
			}
			for _, m := range token.FindAllStringSubmatch(lit, -1) {
				if !known[m[1]] {
					t.Errorf("%s: token %s is not a Setting", f, m[0])
				}
			}
		}
	}
}
