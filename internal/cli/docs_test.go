package cli

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

// unreleasedList reads one list of the site's unreleased.yml in file order:
// the two-space "- name" items under key, with no YAML dependency.
func unreleasedList(data, key string) []string {
	var items []string
	inList := false
	for _, line := range strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "":
		case !strings.HasPrefix(line, " "):
			inList = strings.TrimSpace(line) == key+":"
		case inList:
			if item, ok := strings.CutPrefix(strings.TrimSpace(line), "- "); ok {
				items = append(items, strings.TrimSpace(item))
			}
		}
	}
	return items
}

// unreleasedFlags reads the `flags:` list of the site's unreleased.yml.
func unreleasedFlags(data string) map[string]bool {
	names := make(map[string]bool)
	for _, name := range unreleasedList(data, "flags") {
		names[name] = true
	}
	return names
}

// unreleasedValues reads the `values:` list of the site's unreleased.yml,
// "flag=VALUE" items for new values of a flag that is itself released (#306),
// as the values of each flag in file order. An item without "=" is kept under
// the empty flag name for the caller to reject.
func unreleasedValues(data string) map[string][]string {
	values := make(map[string][]string)
	for _, item := range unreleasedList(data, "values") {
		name, value, _ := strings.Cut(item, "=")
		if value == "" {
			name, value = "", item
		}
		values[name] = append(values[name], value)
	}
	return values
}

// flagsMarkdown renders every flag as a Markdown table, sorted by name. Flags
// in unreleased get the site's "unreleased" tag, and a flag with values in
// unreleasedVals gets a tagged note naming them after its description.
func flagsMarkdown(fs *flag.FlagSet, unreleased map[string]bool, unreleasedVals map[string][]string) string {
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
			// A 0 sentinel whose real default is resolved later (-attempts)
			// names it in the usage text as "(default N)".
			if i := strings.LastIndex(usage, "(default "); i >= 0 && strings.HasSuffix(usage, ")") {
				def = usage[i+len("(default ") : len(usage)-1]
			}
		}
		code := func(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
		// Description cells are Markdown: keep <domain> and *.parent literal.
		text := strings.NewReplacer("|", `\|`, "<", "&lt;", ">", "&gt;", "*", `\*`, "_", `\_`)
		tag := ""
		if unreleased[fl.Name] {
			tag = fmt.Sprintf(` {%% include unreleased.html flag=%q %%}`, fl.Name)
		}
		note := ""
		if vals := unreleasedVals[fl.Name]; len(vals) > 0 {
			note = fmt.Sprintf(` %s: {%% include unreleased.html value=%q %%}`, strings.Join(vals, ", "), fl.Name+"="+vals[0])
		}
		fmt.Fprintf(&b, "| `%s`%s | %s | %s%s |\n", code(flagCol), tag, text.Replace(def), text.Replace(usage), note)
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
	unreleasedVals := unreleasedValues(string(data))
	for name, vals := range unreleasedVals {
		fl := fs.Lookup(name)
		if fl == nil {
			t.Fatalf("%s lists values %v for -%s, which is not a CLI flag (want flag=VALUE)", siteUnreleasedFile, vals, name)
		}
		if unreleased[name] {
			t.Fatalf("%s lists -%s under both flags: and values:; a new flag needs only flags:", siteUnreleasedFile, name)
		}
		for _, v := range vals {
			if !strings.Contains(fl.Usage, v) {
				t.Fatalf("%s lists %s=%s, but the -%s usage text does not name %s", siteUnreleasedFile, name, v, name, v)
			}
		}
	}
	want := flagsMarkdown(fs, unreleased, unreleasedVals)
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

// TestUnreleasedValues reads the values: list per flag, and the flag table
// names those values in a tagged note without tagging the flag itself (#306).
func TestUnreleasedValues(t *testing.T) {
	data := "flags:\r\n  - dry-run\r\nvalues:\r\n  - type=NS\r\n  - type=MX\r\n  - bare\r\nlibrary:\r\n  - Diff\r\n"
	got := unreleasedValues(data)
	if len(got) != 2 || strings.Join(got["type"], ",") != "NS,MX" || strings.Join(got[""], ",") != "bare" {
		t.Fatalf("unreleasedValues = %v, want type: NS, MX and the malformed item under \"\"", got)
	}
	if len(unreleasedValues("flags:\n  - dry-run\nvalues:\n")) != 0 {
		t.Fatal("an empty values: list should tag nothing")
	}

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("type", "A", "Record types: A, NS, MX")
	table := flagsMarkdown(fs, nil, map[string][]string{"type": {"NS", "MX"}})
	want := "| `-type <string>` | A | Record types: A, NS, MX NS, MX: {% include unreleased.html value=\"type=NS\" %} |\n"
	if !strings.HasSuffix(table, want) {
		t.Fatalf("flag table row:\n%s\nwant suffix:\n%s", table, want)
	}
	if plain := flagsMarkdown(fs, nil, nil); strings.Contains(plain, "unreleased") {
		t.Fatalf("no unreleased values, but the table has a tag:\n%s", plain)
	}
}

// TestSiteUnreleasedValueTags fails when a page tags a flag value that
// unreleased.yml does not list, which the site would silently leave untagged
// (#306). TestSiteFlagTableUpToDate checks the list itself against the CLI.
// An empty list is the state after a release, when leftover tags render
// nothing, as leftover flag tags do.
func TestSiteUnreleasedValueTags(t *testing.T) {
	data, err := os.ReadFile(siteUnreleasedFile)
	if err != nil {
		t.Fatal(err)
	}
	listed := make(map[string]bool)
	for _, item := range unreleasedList(string(data), "values") {
		listed[item] = true
	}
	if len(listed) == 0 {
		return
	}
	pages, err := filepath.Glob(filepath.Join("docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	const tag = `include unreleased.html value="`
	for _, page := range pages {
		contents, err := os.ReadFile(page) //nolint:gosec // a docs file
		if err != nil {
			t.Fatal(err)
		}
		rest := string(contents)
		for {
			_, after, ok := strings.Cut(rest, tag)
			if !ok {
				break
			}
			value, tail, _ := strings.Cut(after, `"`)
			rest = tail
			if !listed[value] {
				t.Errorf("%s tags value %q, which %s does not list", page, value, siteUnreleasedFile)
			}
		}
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
