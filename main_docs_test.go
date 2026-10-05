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

// flagsMarkdown renders every flag as a Markdown table, sorted by name.
func flagsMarkdown(fs *flag.FlagSet) string {
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
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", code(flagCol), text.Replace(def), text.Replace(usage))
	})
	return b.String()
}

// TestSiteFlagTableUpToDate fails when the site's flag table no longer
// matches the CLI. Regenerate it with `make docs-flags`.
func TestSiteFlagTableUpToDate(t *testing.T) {
	_, _, fs, _ := parseFlags(nil)
	want := flagsMarkdown(fs)
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
