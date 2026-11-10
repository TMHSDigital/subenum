package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// siteFlagsFile is the site's flag table, generated from the real FlagSet so
// the docs cannot drift from `subenum -h` (#64).
var siteFlagsFile = filepath.Join("docs", "_includes", "flags.md")
var readmeFlagsFile = "README.md"

// siteUnreleasedFile lists what the site tags "unreleased" (#213).
var siteUnreleasedFile = filepath.Join("docs", "_data", "unreleased.yml")

// unreleasedFlags reads the `flags:` list of the site's unreleased.yml: the
// two-space "- name" items under that key, with no YAML dependency.
func unreleasedFlags(data string) map[string]bool {
	names := make(map[string]bool)
	inFlags := false
	for _, line := range strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "":
		case !strings.HasPrefix(line, " "):
			inFlags = strings.TrimSpace(line) == "flags:"
		case inFlags:
			if name, ok := strings.CutPrefix(strings.TrimSpace(line), "- "); ok {
				names[strings.TrimSpace(name)] = true
			}
		}
	}
	return names
}

// flagsMarkdown renders every flag as a Markdown table, sorted by name. Flags
// in unreleased get the site's "unreleased" tag.
func flagsMarkdown(fs *flag.FlagSet, unreleased map[string]bool) string {
	var b strings.Builder
	b.WriteString("<!-- Generated from subenum's flags by `make docs-flags`; do not edit. -->\n\n")
	b.WriteString("| Flag | Default | Description |\n| :--- | :--- | :--- |\n")
	fs.VisitAll(func(fl *flag.Flag) {
		name, usage := flag.UnquoteUsage(fl)
		flagCol := "-" + fl.Name
		if name != "" {
			flagCol += " <" + name + ">"
		}
		def := fl.DefValue
		switch def {
		case "", "0", "false":
			def = "-"
		}
		code := func(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
		// Description cells are Markdown: keep <domain> and *.parent literal.
		text := strings.NewReplacer("|", `\|`, "<", "&lt;", ">", "&gt;", "*", `\*`, "_", `\_`)
		tag := ""
		if unreleased[fl.Name] {
			tag = fmt.Sprintf(` {%% include unreleased.html flag=%q %%}`, fl.Name)
		}
		fmt.Fprintf(&b, "| `%s`%s | %s | %s |\n", code(flagCol), tag, text.Replace(def), text.Replace(usage))
	})
	return b.String()
}

// TestSiteFlagTableUpToDate fails when the site's flag table no longer
// matches the CLI. Regenerate it with `make docs-flags`.
func TestSiteFlagTableUpToDate(t *testing.T) {
	_, _, fs, _ := parseFlags(nil)
	data, err := os.ReadFile(siteUnreleasedFile)
	if err != nil {
		t.Fatal(err)
	}
	unreleased := unreleasedFlags(string(data))
	for name := range unreleased {
		if fs.Lookup(name) == nil {
			t.Fatalf("%s lists -%s, which is not a CLI flag", siteUnreleasedFile, name)
		}
	}
	want := flagsMarkdown(fs, unreleased)
	if os.Getenv("UPDATE_DOCS") == "1" {
		if err := os.WriteFile(siteFlagsFile, []byte(want), 0o644); err != nil { //nolint:gosec // a docs file
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(siteFlagsFile)
	if err != nil {
		t.Fatalf("%v (run `make docs-flags`)", err)
	}
	if strings.ReplaceAll(string(got), "\r\n", "\n") != want {
		t.Fatalf("%s is out of date with the CLI flags; run `make docs-flags`", siteFlagsFile)
	}
}

// TestUnreleasedFlags reads only the flags: list, ignoring comments and the
// other lists that share the file.
func TestUnreleasedFlags(t *testing.T) {
	data := "# note\r\nflags:\r\n  - dry-run\r\n  # skipped\r\n  - log-format\r\naction:\r\n  - changed\r\nlibrary:\r\n  - MaxDuration\r\n"
	got := unreleasedFlags(data)
	if len(got) != 2 || !got["dry-run"] || !got["log-format"] {
		t.Fatalf("unreleasedFlags = %v, want dry-run and log-format", got)
	}
	if len(unreleasedFlags("flags:\naction:\n  - changed\n")) != 0 {
		t.Fatal("an empty flags: list should tag nothing")
	}
}

// TestREADMEFlagTableCoversCLI keeps the hand-written README table complete
// when a CLI flag is added. The website table is generated, but the README is
// maintained separately for quick reference (#137).
func TestREADMEFlagTableCoversCLI(t *testing.T) {
	contents, err := os.ReadFile(readmeFlagsFile) //nolint:gosec // a docs file
	if err != nil {
		t.Fatal(err)
	}

	inTable := false
	tableStarted := false
	documented := make(map[string]bool)
	for _, line := range strings.Split(strings.ReplaceAll(string(contents), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "### CLI flags" {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			if tableStarted {
				break
			}
			continue
		}
		tableStarted = true

		cells := strings.SplitN(line, "|", 3)
		if len(cells) < 2 {
			continue
		}
		cell := strings.TrimSpace(cells[1])
		if !strings.HasPrefix(cell, "`-") {
			continue
		}
		name := strings.TrimPrefix(cell, "`-")
		if end := strings.IndexAny(name, " \t<`"); end >= 0 {
			name = name[:end]
		}
		if name != "" {
			documented[name] = true
		}
	}
	if !inTable || !tableStarted {
		t.Fatalf("%s has no CLI flags table", readmeFlagsFile)
	}

	_, _, fs, _ := parseFlags(nil)
	var missing []string
	fs.VisitAll(func(fl *flag.Flag) {
		if !documented[fl.Name] {
			missing = append(missing, "-"+fl.Name)
		}
	})
	if len(missing) > 0 {
		t.Fatalf("%s CLI flags table is missing flags: %s", readmeFlagsFile, strings.Join(missing, ", "))
	}
}
