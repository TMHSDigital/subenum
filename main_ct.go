package main

import (
	"context"

	"github.com/TMHSDigital/subenum/internal/ct"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// ctBaseURL, when set by a test, replaces crt.sh.
var ctBaseURL string

// targetCT is a target's Certificate Transparency lookup (#130).
type targetCT struct {
	names   []string // relative to the target
	fetched bool     // the lookup succeeded (names may still be empty)
	err     string
}

// certificateTransparency returns the CT names for target: the ones a
// resumed run saved, so its candidate list matches the interrupted run's,
// or a fresh lookup. A failed lookup is a warning, not a failed scan.
func certificateTransparency(ctx context.Context, target string, saved *resumeTarget, out *output.Writer) targetCT {
	if saved != nil && saved.CTFetched {
		return targetCT{names: saved.CT, fetched: true}
	}
	client := ct.Client{BaseURL: ctBaseURL, UserAgent: ProgramName + "/" + resolveVersion() + " (+https://github.com/TMHSDigital/subenum)"}
	names, err := client.Names(ctx, target)
	if err != nil {
		out.Info("Warning: %v; scanning %s without Certificate Transparency names", err, target)
		return targetCT{err: err.Error()}
	}
	return targetCT{names: names, fetched: true}
}

// withCTEntries appends the CT names that are not already wordlist entries,
// after them, so the wordlist's own resume positions stay put. Names too long
// for the target are dropped by wordlist.Build.
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

// withCTSeeds returns the -seeds names plus the CT names, as full names, for
// the -permute pass.
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
