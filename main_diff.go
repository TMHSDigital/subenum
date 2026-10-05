package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
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
}

// loadPrevious reads the names from a previous subenum results file in any
// output format: JSONL (summary lines are skipped), a JSON array, CSV, or
// text (bare names, "Found: name", or -show-records lines).
func loadPrevious(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	names := map[string]struct{}{}
	add := func(name string) {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name != "" {
			names[name] = struct{}{}
		}
	}
	text := strings.TrimPrefix(string(data), string(rune(0xFEFF)))
	trimmed := strings.TrimSpace(text)

	if strings.HasPrefix(trimmed, "[") {
		var results []output.Result
		if err := json.Unmarshal([]byte(trimmed), &results); err != nil {
			return nil, err
		}
		for _, r := range results {
			add(r.Subdomain)
		}
		return names, nil
	}
	if strings.HasPrefix(trimmed, "subdomain,") {
		rows, err := csv.NewReader(strings.NewReader(trimmed)).ReadAll()
		if err != nil {
			return nil, err
		}
		for _, row := range rows[1:] {
			if len(row) > 0 {
				add(row[0])
			}
		}
		return names, nil
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "{"):
			var r struct {
				Type      string `json:"type"`
				Subdomain string `json:"subdomain"`
			}
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return nil, err
			}
			if r.Type != "summary" {
				add(r.Subdomain)
			}
		default:
			for _, p := range []string{"Found (SIMULATED):", "Found:", "+ ", "- "} {
				line = strings.TrimSpace(strings.TrimPrefix(line, p))
			}
			if fields := strings.Fields(line); len(fields) > 0 {
				add(fields[0])
			}
		}
	}
	return names, nil
}

// observe records a found name and reports whether it is new.
func (d *differ) observe(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	name = strings.ToLower(name)
	d.current[name] = struct{}{}
	if _, seen := d.previous[name]; seen {
		return false
	}
	d.added++
	return true
}

// removedNames returns previous names under one of targets that this run did
// not find, sorted. Names -exclude kept out of scope were never tested, so
// they are not reported as removed.
func (d *differ) removedNames(targets, exclude []string) []string {
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
	d.removed = len(out)
	return out
}

// emitRemoved writes the removed names, or explains why it does not: names
// missing from a degraded or interrupted run may just be lookups that failed.
func emitRemoved(d *differ, targets []string, f cliFlags, summary output.Summary, out *output.Writer) {
	if summary.Verdict != scan.VerdictComplete {
		out.Info("Note: -diff is not reporting removed names because the run was %s (%s)", summary.Verdict, summary.Reason)
		return
	}
	for _, name := range d.removedNames(targets, f.excludes) {
		out.Emit(output.Result{Subdomain: name, Records: []dns.Record{}, Change: "removed"})
	}
}
