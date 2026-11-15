package tui

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"

	tea "charm.land/bubbletea/v2"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/permute"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// The Sources and Permute fields run around the scan, as -sources and
// -permute do on the command line (#274): the passive sources are asked
// while the wordlist loads, and the permutation pass is a second scan after
// the main one.

// Result sources that are not a passive source's name, as the CLI writes them.
var (
	fromWordlist = []string{"wordlist"}
	fromPermute  = []string{"permute"}
)

// sourceLookup is one passive source's answer for the scan's domain.
type sourceLookup struct {
	name      string   // -sources name: ct, wayback
	names     []string // relative to the domain
	added     int      // names that were not candidates already
	fetched   bool     // the lookup succeeded (names may still be empty)
	err       string
	truncated string // why a source that succeeded stopped at one of its limits
}

// fetchSources asks every source for the domain's names at once. A failed
// lookup is reported on the scan screen; the scan goes on without its names.
func fetchSources(ctx context.Context, domain string, sources []string, o Options) []sourceLookup {
	opts := passive.Options{
		UserAgent: "subenum/" + o.Version + " (+https://github.com/TMHSDigital/subenum)",
		BaseURLs:  o.SourceURLs,
	}
	res := make([]sourceLookup, len(sources))
	var wg sync.WaitGroup
	for i, name := range sources {
		res[i].name = name
		src, err := passive.New(name, opts)
		if err != nil { // the form admitted only known names
			res[i].err = err.Error()
			continue
		}
		wg.Go(func() {
			names, err := src.Names(ctx, domain)
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
	return res
}

// mergeSources appends the sources' names that are not entries already, after
// them, and sets each lookup's added count. from has every name a source
// proposed (relative to domain) with who had it, the wordlist first; names
// missing from it are the wordlist's alone.
func mergeSources(domain string, entries []string, lookups []sourceLookup) (merged []string, from map[string][]string) {
	var have map[string]bool
	for i := range lookups {
		l := &lookups[i]
		if len(l.names) == 0 {
			continue
		}
		if have == nil {
			have = make(map[string]bool, len(entries)+len(l.names))
			for _, e := range entries {
				have[e] = true
			}
			from = map[string][]string{}
		}
		// Before the merge, while have still tells a wordlist entry from a
		// name only an earlier source had (those are in from).
		proposed, _, _ := wordlist.Build(l.names, domain)
		for _, n := range proposed {
			if _, seen := from[n]; !seen && have[n] {
				from[n] = fromWordlist
			}
			from[n] = append(slices.Clip(from[n]), l.name)
		}
		entries, l.added = passive.Merge(entries, have, l.names, domain)
	}
	return entries, from
}

// permutationPass is the second pass of a scan with Permute on.
type permutationPass struct {
	seeds      int
	candidates int
	found      int
	done       bool       // the pass ran and reported its counts
	final      scan.Event // its last event, when done
}

// unfinished reports whether there were candidates the pass did not get
// through: the user aborted before it, or it failed before testing them.
func (p *permutationPass) unfinished() bool {
	return p != nil && p.candidates > 0 && !p.done
}

// summarize adds the pass to the target's summary the way the CLI's report
// does (#298): its counts and queries, and its verdict when that is worse
// than the main pass's. errText is the scan's first error, if any.
func (p *permutationPass) summarize(t *output.TargetSummary, interrupted bool, errText string) {
	if p == nil {
		return
	}
	t.Permutation = &output.PermutationSummary{Seeds: p.seeds, Candidates: p.candidates, Found: p.found}
	const prefix = "permutation pass: "
	switch {
	case p.done:
		verdict, reason := p.final.Stats.Verdict(interrupted)
		t.Permutation.Verdict = verdict
		t.Permutation.Processed, t.Permutation.QueriesSent = p.final.Processed, p.final.Stats.QueriesSent
		t.QueriesSent += p.final.Stats.QueriesSent
		if scan.VerdictRank(verdict) > scan.VerdictRank(t.Verdict) {
			t.Verdict, t.Reason = verdict, prefix+scan.Render(reason, settingLabel)
		}
	case p.unfinished() && scan.VerdictRank(t.Verdict) < scan.VerdictRank(scan.VerdictDegraded):
		if errText == "" {
			errText = "it did not run to completion"
		}
		t.Verdict, t.Reason = scan.VerdictDegraded, prefix+errText
	}
}

// addStats sums two passes' counters for the finished screen's counters
// line. The verdict is not taken from the sum: each pass has its own.
func addStats(a, b scan.Stats) scan.Stats {
	a.Found += b.Found
	a.NXDomain += b.NXDomain
	a.Timeout += b.Timeout
	a.Refused += b.Refused
	a.Other += b.Other
	a.WildcardFiltered += b.WildcardFiltered
	a.QueriesSent += b.QueriesSent
	a.Skipped += b.Skipped
	a.Excluded += b.Excluded
	a.Takeover += b.Takeover
	a.Internal += b.Internal
	a.Retried += b.Retried
	a.Recovered += b.Recovered
	a.RateBackoffs += b.RateBackoffs
	return a
}

// permutationReadyMsg carries the permutation pass's candidates.
type permutationReadyMsg struct {
	seeds      int
	candidates []string
	tooLong    int // candidates dropped: their full name would pass 253 characters
}

// permutationCmd builds the permutation pass's candidates in a tea.Cmd
// goroutine, since the set of entries is as large as the wordlist. The seeds
// are the names the main pass found and the ones the sources proposed;
// candidates that are entries or seeds already are left out, so nothing is
// queried twice.
func permutationCmd(domain string, entries, found []string, from map[string][]string) tea.Cmd {
	return func() tea.Msg {
		set := map[string]bool{}
		for _, name := range found {
			name = strings.ToLower(strings.TrimSuffix(name, "."))
			if rel, ok := strings.CutSuffix(name, "."+domain); ok && rel != "" {
				set[rel] = true
			}
		}
		for rel := range from {
			set[rel] = true
		}
		rel := slices.Sorted(maps.Keys(set))
		if len(rel) == 0 {
			return permutationReadyMsg{}
		}
		skip := make(map[string]bool, len(entries)+len(rel))
		for _, e := range entries {
			skip[e] = true
		}
		for _, s := range rel {
			skip[s] = true
		}
		candidates, _, tooLong := wordlist.Build(permute.Generate(rel, permute.Words, skip), domain)
		return permutationReadyMsg{seeds: len(rel), candidates: candidates, tooLong: tooLong}
	}
}
