package main

import (
	"bufio"
	"context"
	"sort"
	"strings"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/permute"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// permutationResult is the second-pass part of a target's result (#72).
type permutationResult struct {
	seeds      int
	candidates int
	found      int
	pass       targetResult
}

// relativeSeeds returns the names under target, relative to it ("api" for
// api.example.com), from this target's hits and the -seeds file.
func relativeSeeds(target string, found []string, seeds map[string]struct{}) []string {
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

// runPermutationPass scans the permutations of a target's found names as a
// second, fully guarded scan (preflight, wildcard filtering, -rate,
// -max-queries, -exclude). Candidates already in the wordlist or found are
// skipped, so nothing is queried twice. It returns nil when there was
// nothing to permute.
func runPermutationPass(ctx context.Context, f cliFlags, target string, entries []string, found []string, seeds map[string]struct{},
	maxAttempts int, recordTypes []string, out *output.Writer, outWriter *bufio.Writer, emit func(scan.Event)) *permutationResult {
	rel := relativeSeeds(target, found, seeds)
	if len(rel) == 0 {
		return nil
	}
	skip := make(map[string]bool, len(entries)+len(rel))
	for _, e := range entries {
		skip[e] = true
	}
	for _, s := range rel {
		skip[s] = true
	}
	candidates := permute.Generate(rel, permute.Words, skip)
	res := &permutationResult{seeds: len(rel), candidates: len(candidates)}
	if len(candidates) == 0 {
		return res
	}
	out.Info("Permutation pass for %s: %d candidates from %d seed names", target, len(candidates), len(rel))
	res.pass = scanTarget(ctx, f, target, candidates, maxAttempts, recordTypes, out, outWriter, func(ev scan.Event) {
		res.found++
		emit(ev)
	})
	return res
}
