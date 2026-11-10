package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

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
	b := baseline{names: map[string]struct{}{}, records: map[string][]dns.Record{}}
	add := func(name string, records ...dns.Record) string {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
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

// observe records a found name and says how it differs from the baseline:
// "added", "changed" (with the baseline's records), or "" for unchanged.
func (d *differ) observe(name string, records []dns.Record) (change string, previous []dns.Record) {
	d.mu.Lock()
	defer d.mu.Unlock()
	name = strings.ToLower(name)
	d.current[name] = struct{}{}
	if _, seen := d.previous[name]; !seen {
		d.added++
		return "added", nil
	}
	if prev, ok := d.records[name]; ok && recordsChanged(prev, records, d.types) {
		d.changed++
		return "changed", prev
	}
	return "", nil
}

// recordsChanged compares a name's baseline and current records over the
// record types this run looked up, as sets. When either side has a CNAME,
// only the CNAME targets are compared: a re-pointed alias is the change that
// matters (#189), while the addresses behind a CDN alias rotate with every
// TTL and would make every CDN host look changed.
func recordsChanged(prev, cur []dns.Record, types []string) bool {
	set := func(rs []dns.Record, only string) map[string]struct{} {
		s := map[string]struct{}{}
		for _, r := range rs {
			t := strings.ToUpper(r.Type)
			if (only != "" && t != only) || !slices.Contains(types, t) {
				continue
			}
			s[t+" "+strings.ToLower(strings.TrimSuffix(r.Value, "."))] = struct{}{}
		}
		return s
	}
	isCNAME := func(r dns.Record) bool { return strings.EqualFold(r.Type, "CNAME") }
	only := ""
	if slices.Contains(types, "CNAME") && (slices.ContainsFunc(prev, isCNAME) || slices.ContainsFunc(cur, isCNAME)) {
		only = "CNAME"
	}
	a, b := set(prev, only), set(cur, only)
	if len(a) != len(b) {
		return true
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return true
		}
	}
	return false
}

// missingNames returns previous names under one of targets that this run did
// not find, sorted: candidates for removal. Names -exclude kept out of scope
// were never tested, so they are left out.
func (d *differ) missingNames(targets, exclude []string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for name := range d.previous {
		if _, ok := d.current[name]; ok || scan.IsExcluded(exclude, name) {
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
	out.Info("Checking %d previous names this run did not find", len(missing))
	cfg := scanOptions(s.f, &s.in, scanPass{maxQueries: s.f.maxQueries}, nil).Config()
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
