package cli

import (
	"context"
	"strings"

	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// permutationResult is the second-pass part of a target's result (#72).
type permutationResult struct {
	seeds      int
	candidates int
	found      int
	pass       targetResult
}

// permuteInput is what a target's -permute pass starts from.
type permuteInput struct {
	target       string
	entries      []string            // the target's wordlist entries, not permuted again
	found        []string            // the main pass's names
	seeds        map[string]struct{} // -seeds names, and -ct names under target
	prev         *resumePass         // the pass's state from an interrupted run, if it had started
	restoredHits int                 // permutation results that run already found
}

// mainPassNames returns the names of a target's results that the main pass
// found, leaving out permutation hits and -ptr hits (#436): they are the
// -permute seeds, which a resumed pass must rebuild identically.
func mainPassNames(results []output.Result) []string {
	names := make([]string, 0, len(results))
	for _, r := range results {
		if !r.Permutation && !ptrHit(r) {
			names = append(names, r.Subdomain)
		}
	}
	return names
}

// recordTargets returns the CNAME, MX, NS and HTTPS (#438) targets of
// results that are not results themselves, for a resumed -follow-records
// scan to queue again (#432). The scan keeps the ones under its target and
// in scope.
func recordTargets(results []output.Result) []string {
	found := make(map[string]bool, len(results))
	for _, r := range results {
		found[strings.ToLower(r.Subdomain)] = true
	}
	var out []string
	for _, r := range results {
		for _, rec := range r.Records {
			var name string
			switch rec.Type {
			case "CNAME", "NS":
				name = rec.Value
			case "MX":
				if fields := strings.Fields(rec.Value); len(fields) > 0 {
					name = fields[len(fields)-1]
				}
			case "HTTPS":
				name = dns.HTTPSTarget(rec)
			}
			if name = strings.ToLower(strings.TrimSuffix(name, ".")); name != "" && !found[name] {
				found[name] = true // once
				out = append(out, name)
			}
		}
	}
	return out
}

// finishedPermutation is the -permute pass of a target finished before the
// interrupt, rebuilt from the state without scanning: the same seeds and
// candidates runPermutationPass would count, and the saved pass (#315).
func finishedPermutation(p permuteInput) *permutationResult {
	rel := candidates.RelativeSeeds(p.target, p.found, p.seeds)
	if len(rel) == 0 {
		return nil
	}
	perms, _, _ := candidates.Permutations(p.target, p.entries, rel)
	res := &permutationResult{seeds: len(rel), candidates: len(perms), found: p.restoredHits}
	if p.prev != nil {
		res.pass = targetResult{done: true, final: p.prev.event()}
	}
	return res
}

// runPermutationPass scans the permutations of a target's found names as a
// second, fully guarded scan (preflight, wildcard filtering, -rate,
// -max-queries, -exclude). Candidates already in the wordlist or found are
// skipped, so nothing is queried twice. It returns nil when there was
// nothing to permute.
//
// found must be the main pass's names only: they decide the candidate list,
// which a resumed pass has to rebuild identically.
func runPermutationPass(ctx context.Context, s *session, p permuteInput) *permutationResult {
	out, target := s.out, p.target
	rel := candidates.RelativeSeeds(target, p.found, p.seeds)
	if len(rel) == 0 {
		return nil
	}
	perms, tooLong, capped := candidates.Permutations(target, p.entries, rel)
	res := &permutationResult{seeds: len(rel), candidates: len(perms), found: p.restoredHits}
	if len(perms) == 0 {
		return res
	}
	if capped {
		out.Info("Permutation pass for %s: %d seed names give more than %d candidates; the pass stops building them there, taking the seeds in sorted order", target, len(rel), candidates.MaxPermutations)
	}
	if tooLong > 0 {
		out.Info("Permutation pass for %s: skipped %d candidates longer than 253 characters", target, tooLong)
	}

	// The pass is one level deep: under -recursive, children of a found
	// permutation would otherwise be built from the candidate list itself,
	// giving names such as <candidate>.api-dev.<target>, and multiply the
	// pass past the recursion ceiling (#111).
	pass := scanPass{domain: target, entries: perms, maxQueries: s.f.maxQueries, flat: true}
	if p.prev != nil {
		// A copy: the saved state keeps its pending names should this pass
		// stop before it reports (#315).
		prev := *p.prev
		p.prev = &prev
		left, ok := remainingBudget(s.f.maxQueries, prev.Processed)
		if !ok {
			out.Info("Permutation pass for %s: the -max-queries budget of %d was spent before the run stopped", target, s.f.maxQueries)
			res.pass = targetResult{done: true, final: prev.event()}
			return res
		}
		pass.resumeFrom, pass.maxQueries = prev.RootDone, left
		prev.handOverPending(&pass, s.f.retryIncon)
		out.Info("Resuming the permutation pass for %s at candidate %d of %d", target, prev.RootDone, len(perms))
	} else {
		out.Info("Permutation pass for %s: %d candidates from %d seed names", target, len(perms), len(rel))
	}
	res.pass = scanTarget(ctx, s, pass, func(ev scan.Event) {
		res.found++
		s.emitPermutation(ev)
	})
	if p.prev != nil && res.pass.done {
		res.pass.final = p.prev.merge(res.pass.final)
	}
	return res
}
