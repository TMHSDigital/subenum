package cli

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// targetSource is one passive source's lookup for a target (#130, #193).
type targetSource struct {
	source  string   // -sources name: ct, wayback
	names   []string // relative to the target
	fetched bool     // the lookup succeeded (names may still be empty)
	err     string
	// truncated says why a source that succeeded stopped at one of its
	// limits, so some hosts may be missing (#272).
	truncated string
}

// passiveNames asks every source for target's names at once (#271): the
// ones a resumed run saved, so its candidate list matches the interrupted
// run's, or a fresh lookup. The results, and the warning for each failed
// lookup (a warning, not a failed scan), keep the order of sources.
// baseURLs, set by tests, replace the sources' endpoints by name.
func passiveNames(ctx context.Context, sources []string, target string, saved *resumeTarget, out *output.Writer, baseURLs map[string]string) []targetSource {
	if len(sources) == 0 {
		return nil
	}
	opts := passive.Options{
		UserAgent: ProgramName + "/" + resolveVersion() + " (+https://github.com/TMHSDigital/subenum)",
		BaseURLs:  baseURLs,
	}
	res := make([]targetSource, len(sources))
	var wg sync.WaitGroup
	for i, name := range sources {
		res[i].source = name
		if names, ok := saved.sourceNames(name); ok {
			res[i].names, res[i].fetched = names, true
			continue
		}
		if saved != nil && saved.Done {
			// The target is not scanned again, so its candidates are not
			// needed: no lookup (#315).
			continue
		}
		src, err := passive.New(name, opts)
		if err != nil { // ParseList admitted only known names
			res[i].err = err.Error()
			continue
		}
		wg.Go(func() {
			names, err := src.Names(ctx, target)
			var tr *passive.Truncated
			switch {
			case errors.As(err, &tr):
				res[i].truncated = tr.Error()
			case err != nil:
				res[i].err = err.Error()
				return
			}
			res[i].names, res[i].fetched = names, true
		})
	}
	wg.Wait()
	for _, r := range res {
		switch {
		case !r.fetched && r.err != "":
			out.Info("Warning: %s; scanning %s without %s names", r.err, target, passive.Labels[r.source])
		case r.truncated != "":
			out.Info("Note: %s (%s, %d names)", r.truncated, target, len(r.names))
		}
	}
	return res
}

// sourceNames returns the names an interrupted run fetched from source, if
// it did. State files from before -sources keep CT names in CT/CTFetched.
func (t *resumeTarget) sourceNames(source string) ([]string, bool) {
	if t == nil {
		return nil, false
	}
	if names, ok := t.Sources[source]; ok {
		return names, true
	}
	if source == "ct" && t.CTFetched {
		return t.CT, true
	}
	return nil, false
}

// sourceByName returns the lookup of one source, if it ran.
func sourceByName(sources []targetSource, name string) targetSource {
	for _, s := range sources {
		if s.source == name {
			return s
		}
	}
	return targetSource{}
}

// candidates gathers a target's candidate entries and -permute seeds as the
// passive sources and the zone transfer add names to the wordlist's (#248).
// No map as large as the wordlist is built: each source's names are checked
// against the entries in one pass (#321).
type candidates struct {
	target  string
	entries []string            // the wordlist's, then the new names in order
	seeds   map[string]struct{} // -seeds names plus every added name, full
	owned   bool                // seeds is this target's copy, not the shared -seeds map

	// Provenance (#273): from has every name a source proposed, as a bit per
	// label of who had it (bit 0 is the wordlist). Names missing from it are
	// the wordlist's alone, so a scan without sources keeps no map.
	labels []string
	from   map[string]uint8
	lists  map[uint8][]string // the labels of each bit set in use, shared by its results
}

// Result sources that are not a passive source's -sources name (#273).
const (
	sourceWordlist = "wordlist"
	sourceAXFR     = "axfr"
	sourcePermute  = "permute"
)

var (
	fromWordlist = []string{sourceWordlist}
	fromPermute  = []string{sourcePermute}
)

// add appends source's names that are not already entries, after them, so
// the wordlist's own resume positions stay put, and returns how many were
// new. Names too long for the target are dropped by wordlist.Build.
func (c *candidates) add(source string, names []string) int {
	if len(names) == 0 {
		return 0
	}
	if c.from == nil {
		c.labels, c.from = []string{sourceWordlist}, map[string]uint8{}
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

// sourcesOf names what proposed a main-pass result (#273). A name no source
// gave is the wordlist's: an entry, or under -recursive an entry below a
// found name.
func (c *candidates) sourcesOf(name string) []string {
	if c == nil {
		return fromWordlist
	}
	mask, ok := c.from[strings.TrimSuffix(name, "."+c.target)]
	if !ok {
		return fromWordlist
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
