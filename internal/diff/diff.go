// Package diff compares two runs' results: which names are new or gone, and
// which names found in both have different records. The CLI's -diff and
// pkg/subenum's Diff share it.
package diff

import (
	"slices"
	"strings"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// Name is the form names are compared in: trimmed, lowercased, without a
// trailing dot.
func Name(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// RecordsChanged compares a name's previous and current records as sets,
// over the record types in types (every type when types is empty). When
// either side has a CNAME, and CNAME is among the compared types, only the
// CNAME targets are compared: a re-pointed alias is the change that matters
// (#189), while the addresses behind a CDN alias rotate with every TTL and
// would make every CDN host look changed.
func RecordsChanged(prev, cur []dns.Record, types []string) bool {
	compared := func(t string) bool { return len(types) == 0 || slices.Contains(types, t) }
	set := func(rs []dns.Record, only string) map[string]struct{} {
		s := map[string]struct{}{}
		for _, r := range rs {
			t := strings.ToUpper(r.Type)
			if (only != "" && t != only) || !compared(t) {
				continue
			}
			s[t+" "+strings.ToLower(strings.TrimSuffix(r.Value, "."))] = struct{}{}
		}
		return s
	}
	isCNAME := func(r dns.Record) bool { return strings.EqualFold(r.Type, "CNAME") }
	only := ""
	if compared("CNAME") && (slices.ContainsFunc(prev, isCNAME) || slices.ContainsFunc(cur, isCNAME)) {
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
