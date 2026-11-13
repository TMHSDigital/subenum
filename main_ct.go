package main

import (
	"context"

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
}

// passiveNames asks each source in turn for target's names: the ones a
// resumed run saved, so its candidate list matches the interrupted run's,
// or a fresh lookup. A failed lookup is a warning, not a failed scan.
func passiveNames(ctx context.Context, sources []string, target string, saved *resumeTarget, out *output.Writer) []targetSource {
	if len(sources) == 0 {
		return nil
	}
	opts := passive.Options{
		UserAgent: ProgramName + "/" + resolveVersion() + " (+https://github.com/TMHSDigital/subenum)",
		BaseURLs:  map[string]string{"ct": ctBaseURL, "wayback": waybackBaseURL},
	}
	res := make([]targetSource, 0, len(sources))
	for _, name := range sources {
		if names, ok := saved.sourceNames(name); ok {
			res = append(res, targetSource{source: name, names: names, fetched: true})
			continue
		}
		src, err := passive.New(name, opts)
		if err != nil { // ParseList admitted only known names
			res = append(res, targetSource{source: name, err: err.Error()})
			continue
		}
		names, err := src.Names(ctx, target)
		if err != nil {
			out.Info("Warning: %v; scanning %s without %s names", err, target, passive.Labels[name])
			res = append(res, targetSource{source: name, err: err.Error()})
			continue
		}
		res = append(res, targetSource{source: name, names: names, fetched: true})
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

// withCTEntries appends the source names that are not already wordlist
// entries, after them, so the wordlist's own resume positions stay put.
// Names too long for the target are dropped by wordlist.Build.
func withCTEntries(entries, names []string, target string) ([]string, int) {
	if len(names) == 0 {
		return entries, 0
	}
	extra, _, _ := wordlist.Build(names, target)
	have := make(map[string]bool, len(entries))
	for _, e := range entries {
		have[e] = true
	}
	out := entries
	added := 0
	for _, e := range extra {
		if !have[e] {
			out = append(out, e)
			added++
		}
	}
	return out, added
}

// withCTSeeds returns the -seeds names plus the source names, as full
// names, for the -permute pass.
func withCTSeeds(seeds map[string]struct{}, names []string, target string) map[string]struct{} {
	if len(names) == 0 {
		return seeds
	}
	out := make(map[string]struct{}, len(seeds)+len(names))
	for s := range seeds {
		out[s] = struct{}{}
	}
	for _, n := range names {
		out[n+"."+target] = struct{}{}
	}
	return out
}
