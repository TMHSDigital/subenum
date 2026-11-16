package scan

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
}

// TestSettingTable covers #160: every setting has a flag, a Config field and
// a form label, and no two settings share one.
// TestSettingsIn covers #198: the codes of the known settings a message
// names, in order and once each.
func TestSettingsIn(t *testing.T) {
	got := SettingsIn("set {max_queries} or {force}; {unknown} {max_queries} {depth}")
	want := []Setting{SettingMaxQueries, SettingForce, SettingDepth}
	if !slices.Equal(got, want) {
		t.Errorf("SettingsIn = %v, want %v", got, want)
	}
	if got := SettingsIn("no tokens"); got != nil {
		t.Errorf("SettingsIn(no tokens) = %v, want nil", got)
	}
}

func TestSettingTable(t *testing.T) {
	seen := map[string]Setting{}
	for _, s := range Settings {
		n := s.Names()
		for kind, name := range map[string]string{"flag": n.Flag, "field": n.Field, "label": n.Label} {
			if name == "" {
				t.Errorf("setting %q has no %s", s, kind)
				continue
			}
			if prev, dup := seen[kind+":"+name]; dup {
				t.Errorf("settings %q and %q share the %s %q", prev, s, kind, name)
			}
			seen[kind+":"+name] = s
		}
	}
	if n := Setting("unknown").Names(); n != (SettingNames{}) || FlagName("unknown") != "" {
		t.Errorf("unknown setting has names %+v", n)
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
