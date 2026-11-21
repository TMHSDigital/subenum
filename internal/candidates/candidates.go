// Package candidates gathers a target's candidate names for the command line
// and the TUI alike (#347): the wordlist's entries plus what the passive
// sources and the zone transfer propose, which source proposed each name
// (#273), and the -permute pass's seeds and candidates.
package candidates

import (
	"sort"
	"strings"

	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/permute"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// Result sources that are not a passive source's -sources name (#273).
const (
	Wordlist = "wordlist"
	AXFR     = "axfr"
	NSEC     = "nsec" // an -nsec-walk name (#437)
	Permute  = "permute"
	Records  = "records" // a -follow-records target (#432)
	SRV      = "srv"     // a -srv service name (#419)
	PTR      = "ptr"     // a -ptr reverse-lookup name (#436)
)

// FromWordlist, FromPermute, FromRecords and FromPTR are the sources of a
// wordlist name, a -permute hit, a -follow-records hit and a -ptr hit,
// shared by every such result.
var (
	FromWordlist = []string{Wordlist}
	FromPermute  = []string{Permute}
	FromRecords  = []string{Records}
	FromPTR      = []string{PTR}
)

// Set is a target's candidate entries and -permute seeds as the passive
// sources and the zone transfer add names to the wordlist's (#248). No map as
// large as the wordlist is built: each source's names are checked against
// the entries in one pass (#321).
type Set struct {
	target  string
	entries []string            // the wordlist's, then the new names in order
	seeds   map[string]struct{} // -seeds names plus every name a source proposed, full
	owned   bool                // seeds is this set's copy, not the caller's map

	// Provenance (#273): from has every name a source proposed, as a bit per
	// label of who had it (bit 0 is the wordlist). Names missing from it are
	// the wordlist's alone, so a scan without sources keeps no map.
	labels []string
	from   map[string]uint8
	lists  map[uint8][]string // the labels of each bit set in use, shared by its results
}

// New starts a set from the wordlist's entries for target and the -seeds
// names (full names; nil for none). Neither is written to.
func New(target string, entries []string, seeds map[string]struct{}) *Set {
	return &Set{target: target, entries: entries, seeds: seeds}
}

// Entries returns the candidates: the wordlist's entries, then the names the
// sources added, relative to the target.
func (c *Set) Entries() []string { return c.entries }

// Seeds returns the -seeds names and every name a source proposed, full.
func (c *Set) Seeds() map[string]struct{} { return c.seeds }

// Add appends source's names that are not already entries, after them, so
// the wordlist's own resume positions stay put, and returns how many were
// new. Names too long for the target are dropped by wordlist.Build.
func (c *Set) Add(source string, names []string) int {
	return c.add(source, names, true)
}

// AddUnseeded is Add for names that must not seed the -permute pass, such
// as -srv's service names (#419): permuting "_sip._tcp" proposes nothing a
// zone would hold.
func (c *Set) AddUnseeded(source string, names []string) int {
	return c.add(source, names, false)
}

func (c *Set) add(source string, names []string, seed bool) int {
	if len(names) == 0 {
		return 0
	}
	if c.from == nil {
		c.labels, c.from = []string{Wordlist}, map[string]uint8{}
	}
	var added []string
	c.entries, added = passive.Merge(c.entries, names, c.target)
	fresh := make(map[string]struct{}, len(added))
	for _, n := range added {
		fresh[n] = struct{}{}
	}
	// A proposed name that was already an entry and that no earlier source
	// had (those are in from) is a wordlist entry.
	bit := uint8(1) << len(c.labels)
	c.labels = append(c.labels, source)
	proposed, _, _ := wordlist.Build(names, c.target)
	for _, n := range proposed {
		mask, seen := c.from[n]
		if _, isNew := fresh[n]; !seen && !isNew {
			mask = 1
		}
		c.from[n] = mask | bit
	}
	if !seed {
		return len(added)
	}
	if !c.owned {
		own := make(map[string]struct{}, len(c.seeds)+len(names))
		for s := range c.seeds {
			own[s] = struct{}{}
		}
		c.seeds, c.owned = own, true
	}
	for _, n := range names {
		c.seeds[n+"."+c.target] = struct{}{}
	}
	return len(added)
}

// SourcesOf names what proposed a main-pass result (#273). A name no source
// gave is the wordlist's: an entry, or under -recursive an entry below a
// found name. A nil set has no sources.
func (c *Set) SourcesOf(name string) []string {
	if c == nil {
		return FromWordlist
	}
	mask, ok := c.from[strings.TrimSuffix(strings.ToLower(name), "."+c.target)]
	if !ok {
		return FromWordlist
	}
	if list, ok := c.lists[mask]; ok {
		return list
	}
	var list []string
	for i, label := range c.labels {
		if mask&(1<<i) != 0 {
			list = append(list, label)
		}
	}
	if c.lists == nil {
		c.lists = map[uint8][]string{}
	}
	c.lists[mask] = list
	return list
}

// RelativeSeeds returns the names under target, relative to it ("api" for
// api.example.com), from the target's hits and the seeds, sorted.
func RelativeSeeds(target string, found []string, seeds map[string]struct{}) []string {
	set := map[string]bool{}
	addName := func(name string) {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if rel, ok := strings.CutSuffix(name, "."+target); ok && rel != "" {
			set[rel] = true
		}
	}
	for _, n := range found {
		addName(n)
	}
	for n := range seeds {
		addName(n)
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Permutations returns the permutations of rel (seed names relative to
// target) that are not wordlist entries or seeds themselves, in a stable
// order. Candidates whose full name would pass the 253-character limit are
// dropped and counted in tooLong: they would otherwise fail as "other" and
// count against the reliability guard (#111). The permutations are checked
// against entries in one pass, with no map as large as the wordlist (#321).
//
// The permutations are built in one set, wordlist entries are deleted from
// it, and only the survivors are copied out, so no second or third copy of
// the list is held (#400). At most MaxPermutations are built; capped reports
// that the seeds gave more.
func Permutations(target string, entries, rel []string) (candidates []string, tooLong int, capped bool) {
	skip := make(map[string]bool, len(rel))
	for _, s := range rel {
		skip[s] = true
	}
	set, capped := permute.GenerateSet(rel, permute.Words, skip, MaxPermutations)
	for _, e := range entries {
		if len(set) == 0 {
			break
		}
		delete(set, e)
	}
	limit := 253 - 1 - len(strings.TrimSuffix(target, "."))
	candidates = make([]string, 0, len(set))
	for c := range set {
		if len(c) > limit {
			tooLong++
			continue
		}
		candidates = append(candidates, c)
	}
	sort.Strings(candidates)
	return candidates, tooLong, capped
}

// MaxPermutations bounds one target's -permute pass: about 93 candidates
// per seed name, so a target with tens of thousands of source names would
// otherwise build millions of them before -max-queries applies (#400).
const MaxPermutations = 1_000_000
