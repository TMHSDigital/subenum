package main

import (
	"bufio"
	"context"
	"sort"
	"strings"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/permute"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/wordlist"
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

// mainPassNames returns the names of a target's results that the main pass
// found, leaving out permutation hits: they are the -permute seeds.
func mainPassNames(results []output.Result) []string {
	names := make([]string, 0, len(results))
	for _, r := range results {
		if !r.Permutation {
			names = append(names, r.Subdomain)
		}
	}
	return names
}

// permutationCandidates returns the permutations of rel (seed names relative
// to target) that are not wordlist entries or seeds themselves, in a stable
// order. Candidates whose full name would pass the 253-character limit are
// dropped and counted in tooLong: they would otherwise fail as "other" and
// count against the reliability guard (#111).
func permutationCandidates(target string, entries, rel []string) (candidates []string, tooLong int) {
	skip := make(map[string]bool, len(entries)+len(rel))
	for _, e := range entries {
		skip[e] = true
	}
	for _, s := range rel {
		skip[s] = true
	}
	candidates, _, tooLong = wordlist.Build(permute.Generate(rel, permute.Words, skip), target)
	return candidates, tooLong
}

// runPermutationPass scans the permutations of a target's found names as a
// second, fully guarded scan (preflight, wildcard filtering, -rate,
// -max-queries, -exclude). Candidates already in the wordlist or found are
// skipped, so nothing is queried twice. It returns nil when there was
// nothing to permute.
//
// found must be the main pass's names only: they decide the candidate list,
// which a resumed pass has to rebuild identically. prev is the pass's state
// from an interrupted run, if it had started; restoredHits counts the
// permutation results that run already found.
func runPermutationPass(ctx context.Context, f cliFlags, target string, entries []string, found []string, seeds map[string]struct{},
	prev *resumePass, restoredHits int, maxAttempts int, recordTypes []string, out *output.Writer, outWriter *bufio.Writer, emit func(scan.Event)) *permutationResult {
	rel := relativeSeeds(target, found, seeds)
	if len(rel) == 0 {
		return nil
	}
	candidates, tooLong := permutationCandidates(target, entries, rel)
	res := &permutationResult{seeds: len(rel), candidates: len(candidates), found: restoredHits}
	if len(candidates) == 0 {
		return res
	}
	if tooLong > 0 {
		out.Info("Permutation pass for %s: skipped %d candidates longer than 253 characters", target, tooLong)
	}

	// The pass is one level deep: under -recursive, children of a found
	// permutation would otherwise be built from the candidate list itself,
	// giving names such as <candidate>.api-dev.<target>, and multiply the
	// pass past the recursion ceiling (#111).
	pf := f
	pf.recursive, pf.depth = false, 1
	pf.resumeFrom, pf.resumeNames = 0, nil
	if prev != nil {
		left, ok := remainingBudget(f.maxQueries, prev.Processed)
		if !ok {
			out.Info("Permutation pass for %s: the -max-queries budget of %d was spent before the interrupt", target, f.maxQueries)
			res.pass = targetResult{done: true, final: prev.event()}
			return res
		}
		pf.resumeFrom, pf.maxQueries = prev.RootDone, left
		out.Info("Resuming the permutation pass for %s at candidate %d of %d", target, prev.RootDone, len(candidates))
	} else {
		out.Info("Permutation pass for %s: %d candidates from %d seed names", target, len(candidates), len(rel))
	}
	res.pass = scanTarget(ctx, pf, target, candidates, maxAttempts, recordTypes, out, outWriter, func(ev scan.Event) {
		res.found++
		emit(ev)
	})
	if prev != nil && res.pass.done {
		res.pass.final = prev.merge(res.pass.final)
	}
	return res
}
