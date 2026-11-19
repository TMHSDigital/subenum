package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
)

const reportUsage = "Usage: subenum report -stats <run.json> [-results <results.jsonl>] [-changes <changes.jsonl>] [-limit 50]"

// defaultReportLimit is how many entries each list of a report shows before
// it says how many more there are.
const defaultReportLimit = 50

// runReport is `subenum report` (#421): it writes a run's Markdown summary
// from its -stats file, and the takeover candidates and -diff changes from
// its results and changes files, the summary the GitHub Action puts on the
// job page. It sends no DNS query.
func runReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	statsPath := fs.String("stats", "", "The run's -stats file (JSON); required")
	resultsPath := fs.String("results", "", "The run's results (JSONL, as -o writes it), for the takeover candidates")
	changesPath := fs.String("changes", "", "The run's -diff output (JSONL, as standard output carries it), for the names added, removed and changed")
	limit := fs.Int("limit", defaultReportLimit, "Most entries each list shows; the rest are counted")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, reportUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *statsPath == "" || fs.NArg() > 0 || *limit < 1 {
		_, _ = fmt.Fprintln(stderr, reportUsage)
		return exitUsage
	}
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "Error: "+format+"\n", a...)
		return exitFailure
	}
	data, err := os.ReadFile(*statsPath)
	if err != nil {
		return fail("reading -stats file: %v", err)
	}
	var summary output.Summary
	if err := json.Unmarshal(data, &summary); err != nil || summary.Type != "summary" {
		if err == nil {
			err = errors.New("not a subenum -stats report")
		}
		return fail("reading -stats file %s: %v", *statsPath, err)
	}
	var results, changes []reportEntry
	if *resultsPath != "" {
		if results, err = readReportEntries(*resultsPath); err != nil {
			return fail("reading -results file: %v", err)
		}
	}
	if *changesPath != "" {
		if changes, err = readReportEntries(*changesPath); err != nil {
			return fail("reading -changes file: %v", err)
		}
	}
	if _, err := io.WriteString(stdout, markdownReport(summary, results, changes, *changesPath != "", *limit)); err != nil {
		return fail("writing the report: %v", err)
	}
	return exitOK
}

// reportEntry is the part of a result line a report reads.
type reportEntry struct {
	Type            string       `json:"type"` // "summary" on a JSONL file's last line
	Subdomain       string       `json:"subdomain"`
	Records         []dns.Record `json:"records"`
	Takeover        string       `json:"takeover_candidate"`
	Change          string       `json:"change"`
	PreviousRecords []dns.Record `json:"previous_records"`
}

// readReportEntries reads a JSONL (or JSON array) results file, leaving out
// its summary line.
func readReportEntries(path string) ([]reportEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	var out []reportEntry
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); errors.Is(err, io.EOF) {
			return out, nil
		} else if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		var batch []reportEntry
		if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
			if err := json.Unmarshal(raw, &batch); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		} else {
			var e reportEntry
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			batch = []reportEntry{e}
		}
		for _, e := range batch {
			if e.Type != "summary" {
				out = append(out, e)
			}
		}
	}
}

// markdownReport renders the summary: the verdict and its reason, a table
// of the targets, the takeover candidates, and with -diff the changes. Each
// list shows at most limit entries and counts the rest. withChanges says a
// changes file was given; without one a -diff run's counts are still shown.
func markdownReport(s output.Summary, results, changes []reportEntry, withChanges bool, limit int) string {
	var b strings.Builder
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(&b, format+"\n", a...) }
	p("### subenum: %s", s.Verdict)
	p("")
	p("%s", s.Reason)
	p("")
	p("| Target | Verdict | Found | Queries | Takeover candidates | Internal addresses |")
	p("|---|---|---|---|---|---|")
	var takeovers int64
	for _, t := range s.Targets {
		found := t.Found
		if t.Permutation != nil {
			found += int64(t.Permutation.Found) // counted apart from the main pass
		}
		takeovers += t.Takeover
		p("| %s | %s | %d | %d | %d | %d |", mdCell(t.Domain), mdCell(t.Verdict), found, t.QueriesSent, t.Takeover, t.Internal)
	}
	list := func(lines []string) {
		for i, line := range lines {
			if i == limit {
				p("- ...and %d more", len(lines)-limit)
				break
			}
			p("%s", line)
		}
	}
	if takeovers > 0 {
		p("")
		p("**Takeover candidates:** %d", takeovers)
		var lines []string
		for _, r := range results {
			if r.Takeover != "" {
				lines = append(lines, fmt.Sprintf("- `%s`: %s", mdSpan(r.Subdomain), mdCell(r.Takeover)))
			}
		}
		list(lines)
	}
	if d := s.Diff; d != nil {
		p("")
		p("**Changes since the previous results:** %d added, %d removed, %d changed.", d.Added, d.Removed, d.Changed)
		if withChanges {
			for _, change := range []struct{ name, prefix string }{{"added", "+"}, {"removed", "-"}, {"changed", "~"}} {
				var lines []string
				for _, c := range changes {
					if c.Change != change.name {
						continue
					}
					line := fmt.Sprintf("- `%s %s`", change.prefix, mdSpan(c.Subdomain))
					if change.name == "changed" {
						line += fmt.Sprintf(": %s -> %s", recordSpan(c.PreviousRecords), recordSpan(c.Records))
					}
					lines = append(lines, line)
				}
				list(lines)
			}
		}
	}
	return b.String()
}

// recordSpan renders records as one code span, "none" when there are none.
// Record values come from the scanned zone, so backticks and control
// characters are replaced.
func recordSpan(records []dns.Record) string {
	if len(records) == 0 {
		return "none"
	}
	parts := make([]string, len(records))
	for i, r := range records {
		parts[i] = r.Type + " " + r.Value
	}
	return "`" + mdSpan(strings.Join(parts, ", ")) + "`"
}

// mdSpan makes s safe inside a Markdown code span: a backtick would end the
// span and a control character break the line, so both become "?".
func mdSpan(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '`' || r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// mdCell makes s safe in a table cell or list text: as mdSpan, and a pipe
// would split the cell.
func mdCell(s string) string {
	return strings.ReplaceAll(mdSpan(s), "|", "\\|")
}
