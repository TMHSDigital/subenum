package cli

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/TMHSDigital/subenum/internal/diff"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// differ compares this run's results with a previous run's (-diff, #84).
// Added names are reported as they are found; removed names only at the
// end, and only when the run was complete.
type differ struct {
	mu       sync.Mutex
	previous map[string]struct{}
	current  map[string]struct{}
	added    int
	removed  int
	changed  int

	// -diff-records (#189): the baseline's records per name, compared for
	// names found again over the record types this run looks up. Nil when
	// the comparison is off or the baseline has no records.
	records map[string][]dns.Record
	types   []string
}

// baseline is a previous results file: its names, and the records behind
// them when the format carries records (JSON, JSONL, CSV; not text).
type baseline struct {
	names      map[string]struct{}
	records    map[string][]dns.Record
	hasRecords bool
}

// loadPrevious reads the names from a previous subenum results file in any
// output format: JSONL (summary lines are skipped), a JSON array, CSV, or
// text (bare names, "Found: name", or -show-records lines).
func loadPrevious(path string) (map[string]struct{}, error) {
	b, err := loadBaseline(path)
	return b.names, err
}

// loadBaseline is loadPrevious keeping the records of formats that have them.
func loadBaseline(path string) (baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return baseline{}, err
	}
	return parseBaseline(data)
}

// parseBaseline is loadBaseline on a results file's contents.
func parseBaseline(data []byte) (baseline, error) {
	b := baseline{names: map[string]struct{}{}, records: map[string][]dns.Record{}}
	add := func(name string, records ...dns.Record) string {
		name = diff.Name(name)
		if name != "" {
			b.names[name] = struct{}{}
			for _, r := range records {
				if r.Type != "" {
					b.records[name] = append(b.records[name], r)
				}
			}
		}
		return name
	}
	text := strings.TrimPrefix(string(data), string(rune(0xFEFF)))
	trimmed := strings.TrimSpace(text)

	if strings.HasPrefix(trimmed, "[") {
		var results []output.Result
		if err := json.Unmarshal([]byte(trimmed), &results); err != nil {
			return baseline{}, err
		}
		for _, r := range results {
			add(r.Subdomain, r.Records...)
		}
		b.hasRecords = true
		return b, nil
	}
	if strings.HasPrefix(trimmed, "subdomain,") {
		rows, err := csv.NewReader(strings.NewReader(trimmed)).ReadAll()
		if err != nil {
			return baseline{}, err
		}
		for _, row := range rows[1:] {
			switch {
			case len(row) >= 3:
				add(row[0], dns.Record{Type: row[1], Value: row[2]})
			case len(row) > 0:
				add(row[0])
			}
		}
		b.hasRecords = true
		return b, nil
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "{"):
			var r struct {
				Type      string       `json:"type"`
				Subdomain string       `json:"subdomain"`
				Records   []dns.Record `json:"records"`
			}
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return baseline{}, err
			}
			if r.Type != "summary" {
				add(r.Subdomain, r.Records...)
				b.hasRecords = true
			}
		default:
			for _, p := range []string{"Found (SIMULATED):", "Found:", "+ ", "- ", "~ "} {
				line = strings.TrimSpace(strings.TrimPrefix(line, p))
			}
			if fields := strings.Fields(line); len(fields) > 0 {
				add(fields[0])
			}
		}
	}
	return b, nil
}

const diffUsage = "Usage: subenum diff [-records] [-type A,AAAA,CNAME] [-format text|json|jsonl|csv] <previous> <current>"

// runDiff is `subenum diff` (#310): it compares two saved results files, in
// any output format, without sending a DNS query. Names only in current are
// "added", names only in previous "missing" (not "removed": nothing was
// looked up to show they are gone), and with -records names in both whose
// records differ are "changed", compared as -diff-records does. It exits
// exitChanges when anything differs.
func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	records := fs.Bool("records", false, "Also report names in both files whose records differ (needs JSON, JSONL or CSV files)")
	typeList := fs.String("type", "", "With -records, compare only these record types (default: every type)")
	formatStr := fs.String("format", "text", "Output format: text, json, jsonl or csv")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, diffUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 2 {
		_, _ = fmt.Fprintln(stderr, diffUsage)
		return exitUsage
	}
	format, err := output.ParseFormat(*formatStr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitUsage
	}
	var types []string // every type
	if strings.TrimSpace(*typeList) != "" {
		if types, err = dns.ParseTypes(*typeList); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return exitUsage
		}
	}
	var files [2]baseline
	for i, path := range fs.Args() {
		if files[i], err = loadBaseline(path); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: reading %s: %v\n", path, err)
			return exitFailure
		}
	}
	prev, cur := files[0], files[1]

	out := output.New(nil, false, format)
	out.SetStdout(stdout)
	out.SetStderr(stderr)
	out.SetPlain(true)
	out.SetDiff(true)
	out.SetShowRecords(*records)
	d := compareBaselines(prev, cur, *records, types)
	if *records && !d.compared {
		out.Info("Note: -records needs JSON, JSONL or CSV files; comparing names only")
	}

	emit := func(name, change string, recs, previous []dns.Record) {
		if recs == nil {
			recs = []dns.Record{}
		}
		out.Emit(output.Result{Result: scan.Result{Subdomain: name, Records: recs}, Change: change, PreviousRecords: previous})
	}
	for _, name := range d.added {
		emit(name, "added", cur.records[name], nil)
	}
	for _, name := range d.changed {
		emit(name, "changed", cur.records[name], prev.records[name])
	}
	for _, name := range d.missing {
		emit(name, "missing", prev.records[name], nil)
	}
	if err := out.Finish(); err != nil {
		out.Error("writing output: %v", err)
		return exitFailure
	}
	summary := fmt.Sprintf("%d added, %d missing", len(d.added), len(d.missing))
	if d.compared {
		summary += fmt.Sprintf(", %d changed", len(d.changed))
	}
	out.Info("%s", summary)
	if len(d.added)+len(d.missing)+len(d.changed) > 0 {
		return exitChanges
	}
	return exitOK
}

// baselineDiff is how two results files differ, each list sorted: names only
// in current, names only in previous, and names in both whose records differ.
// compared says whether records were compared at all.
type baselineDiff struct {
	added, missing, changed []string
	compared                bool
}

// compareBaselines compares two results files (subenum diff and the MCP diff
// tool). With records, names in both are compared record by record over types
// (every type when empty), as -diff-records does, when both files have
// records.
func compareBaselines(prev, cur baseline, records bool, types []string) baselineDiff {
	sorted := func(m map[string]struct{}) []string {
		names := make([]string, 0, len(m))
		for name := range m {
			names = append(names, name)
		}
		sort.Strings(names)
		return names
	}
	d := baselineDiff{compared: records && prev.hasRecords && cur.hasRecords}
	for _, name := range sorted(cur.names) {
		if _, seen := prev.names[name]; !seen {
			d.added = append(d.added, name)
		} else if old, ok := prev.records[name]; d.compared && ok && diff.RecordsChanged(old, cur.records[name], types) {
			d.changed = append(d.changed, name)
		}
	}
	for _, name := range sorted(prev.names) {
		if _, ok := cur.names[name]; !ok {
			d.missing = append(d.missing, name)
		}
	}
	return d
}

// observe records a found name and says how it differs from the baseline:
// "added", "changed" (with the baseline's records), or "" for unchanged. A
// partial answer, where a requested type got no answer (#357), is never
// "changed": its missing records say nothing about the name.
func (d *differ) observe(name string, records []dns.Record, partial bool) (change string, previous []dns.Record) {
	d.mu.Lock()
	defer d.mu.Unlock()
	name = strings.ToLower(name)
	d.current[name] = struct{}{}
	if _, seen := d.previous[name]; !seen {
		d.added++
		return "added", nil
	}
	// d.types is the run's record types, never empty, so only the types
	// this run looked up are compared.
	if prev, ok := d.records[name]; ok && !partial && diff.RecordsChanged(prev, records, d.types) {
		d.changed++
		return "changed", prev
	}
	return "", nil
}

// missingNames returns previous names under one of targets that this run did
// not find, sorted: candidates for removal. Names -exclude kept out of scope
// were never tested, so they are left out.
func (d *differ) missingNames(targets, exclude []string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	excluded := scan.Excluder(exclude)
	for name := range d.previous {
		if _, ok := d.current[name]; ok || excluded(name) {
			continue
		}
		for _, t := range targets {
			if name == t || strings.HasSuffix(name, "."+t) {
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// withRecords turns on -diff-records for a baseline: found names that were in
// it are compared record by record over types. It returns false when the
// baseline's format has no records (text), and the diff stays name-only.
func (d *differ) withRecords(b baseline, types []string) bool {
	if !b.hasRecords {
		return false
	}
	d.records, d.types = b.records, types
	return true
}

// emitRemoved writes the removed names, or explains why it does not: names
// missing from a degraded or interrupted run may just be lookups that failed.
//
// A name this run did not find is not necessarily gone: it may not have been
// a candidate (a different wordlist, no -recursive or -permute), or its own
// lookup may have failed under a run that is still "complete". So each
// missing name is looked up again with the trusted resolver, and only an
// NXDOMAIN is reported as removed (#110). The counts go to summary.Diff; it
// returns the DNS queries sent.
func emitRemoved(ctx context.Context, s *session, summary *output.Summary) int64 {
	d, out, diffSummary := s.diff, s.out, summary.Diff
	if summary.Verdict != scan.VerdictComplete {
		out.Info("Note: -diff is not reporting removed names because the run was %s (%s)", summary.Verdict, summary.Reason)
		return 0
	}
	missing := d.missingNames(s.targets, s.in.excludes)
	if len(missing) == 0 {
		return 0
	}
	// The check spends what is left of the run's budgets (#276): -max-queries
	// per target, less the names the targets tested, and the -max-duration
	// deadline. Names it does not reach are counted unverified below.
	budget := 0
	if s.f.maxQueries > 0 {
		left := int64(s.f.maxQueries) * int64(len(summary.Targets))
		for _, t := range summary.Targets {
			left -= t.Processed
		}
		if left < 1 {
			out.Info("Note: -diff is not checking removed names because the -max-queries budget is spent")
			diffSummary.Unverified = len(missing)
			return 0
		}
		budget = int(min(left, int64(len(missing))))
	}
	out.Info("Checking %d previous names this run did not find", len(missing))
	if budget > 0 && budget < len(missing) {
		out.Info("Note: the remaining -max-queries budget covers %d of them", budget)
	}
	cfg := scanOptions(s.f, &s.in, scanPass{maxQueries: budget}, nil).Config
	cfg.Pool = nil // the trusted resolver decides
	outcomes, sent := scan.Verify(ctx, cfg, missing)
	for _, name := range missing {
		outcome, checked := outcomes[name]
		switch {
		case !checked:
			diffSummary.Unverified++ // never looked up; not a found name (#151)
		case outcome == dns.OutcomeNXDomain:
			d.removed++
			out.Emit(output.Result{Result: scan.Result{Subdomain: name, Records: []dns.Record{}}, Change: "removed"})
		case outcome == dns.OutcomeFound:
			diffSummary.StillResolving++
		default:
			diffSummary.Unverified++
		}
	}
	diffSummary.Removed = d.removed
	if n := diffSummary.StillResolving; n > 0 {
		out.Info("Note: %d previous names still resolve but were not among this run's candidates; not reported as removed", n)
	}
	if n := diffSummary.Unverified; n > 0 {
		out.Info("Note: %d previous names could not be checked (lookup failed); not reported as removed", n)
	}
	return sent
}
