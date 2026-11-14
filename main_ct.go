package main

import (
	"context"
	"errors"
	"sync"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// ctBaseURL and waybackBaseURL, when set by a test, replace crt.sh and the
// Wayback Machine.
var ctBaseURL, waybackBaseURL string

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
func passiveNames(ctx context.Context, sources []string, target string, saved *resumeTarget, out *output.Writer) []targetSource {
	if len(sources) == 0 {
		return nil
	}
	opts := passive.Options{
		UserAgent: ProgramName + "/" + resolveVersion() + " (+https://github.com/TMHSDigital/subenum)",
		BaseURLs:  map[string]string{"ct": ctBaseURL, "wayback": waybackBaseURL},
	}
	res := make([]targetSource, len(sources))
	var wg sync.WaitGroup
	for i, name := range sources {
		res[i].source = name
		if names, ok := saved.sourceNames(name); ok {
			res[i].names, res[i].fetched = names, true
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
// The set of entries is built once, at the first names, however many
// sources follow; it used to be rebuilt per source, a map as large as the
// wordlist each time.
type candidates struct {
	target  string
	entries []string            // the wordlist's, then the new names in order
	seeds   map[string]struct{} // -seeds names plus every added name, full
	have    map[string]bool     // entries, once a source has names
	owned   bool                // seeds is this target's copy, not the shared -seeds map
}

// add appends the names that are not already entries, after them, so the
// wordlist's own resume positions stay put, and returns how many were new.
// Names too long for the target are dropped by wordlist.Build.
func (c *candidates) add(names []string) int {
	if len(names) == 0 {
		return 0
	}
	if c.have == nil {
		c.have = make(map[string]bool, len(c.entries)+len(names))
		for _, e := range c.entries {
			c.have[e] = true
		}
	}
	extra, _, _ := wordlist.Build(names, c.target)
	added := 0
	for _, e := range extra {
		if !c.have[e] {
			c.have[e] = true
			c.entries = append(c.entries, e)
			added++
		}
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
	return added
}
