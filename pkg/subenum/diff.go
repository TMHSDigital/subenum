package subenum

import (
	"sort"

	"github.com/TMHSDigital/subenum/internal/diff"
	"github.com/TMHSDigital/subenum/internal/dns"
)

// Changes is how one set of results differs from an earlier one; see Diff.
// Every list is sorted by name.
type Changes struct {
	// Added are names in the current results that the previous ones lack.
	Added []string

	// Removed are previous names the current results lack. A name can be
	// missing because it no longer exists, but also because it was not a
	// candidate this time or its lookup failed, so look these up again
	// before treating them as gone: the command line reports a name removed
	// only after a fresh NXDOMAIN, and only for a complete run.
	Removed []string

	// Changed are names in both whose records differ.
	Changed []Change
}

// Change is a name found in both runs whose records differ.
type Change struct {
	Name     string
	Previous []Record
	Current  []Record
}

// Diff compares current results with previous ones, such as last week's
// Scan of the same domain, the way the command line's -diff and
// -diff-records do. Names are compared case-insensitively and without a
// trailing dot.
//
// Records are compared as sets, over the record types in types (every type
// when types is nil); pass the Config.Types both scans used, so a type only
// one of them looked up is not reported as a change. When either side has a
// CNAME and CNAME is compared, only the CNAME targets count: a re-pointed
// alias is a change, while the addresses behind a CDN alias rotate and are
// not. A previous result without records, such as one read from a plain
// list of names, is never reported as changed. Diff sends no DNS queries.
func Diff(previous, current []Result, types []string) Changes {
	prev, cur := byName(previous), byName(current)
	var c Changes
	for name, recs := range cur {
		old, seen := prev[name]
		switch {
		case !seen:
			c.Added = append(c.Added, name)
		case len(old) > 0 && diff.RecordsChanged(dnsRecords(old), dnsRecords(recs), types):
			c.Changed = append(c.Changed, Change{Name: name, Previous: old, Current: recs})
		}
	}
	for name := range prev {
		if _, ok := cur[name]; !ok {
			c.Removed = append(c.Removed, name)
		}
	}
	sort.Strings(c.Added)
	sort.Strings(c.Removed)
	sort.Slice(c.Changed, func(i, j int) bool { return c.Changed[i].Name < c.Changed[j].Name })
	return c
}

// byName collects results by normalized name, merging the records of a name
// listed more than once.
func byName(results []Result) map[string][]Record {
	m := make(map[string][]Record, len(results))
	for _, r := range results {
		name := diff.Name(r.Name)
		if name == "" {
			continue
		}
		m[name] = append(m[name], r.Records...)
	}
	return m
}

func dnsRecords(in []Record) []dns.Record {
	out := make([]dns.Record, 0, len(in))
	for _, r := range in {
		out = append(out, dns.Record{Type: r.Type, Value: r.Value})
	}
	return out
}
