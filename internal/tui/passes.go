package tui

import (
	"context"
	"errors"
	"sync"

	tea "charm.land/bubbletea/v2"

	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/report"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// The Sources and Permute fields run around the scan, as -sources and
// -permute do on the command line (#274): the passive sources are asked
// while the wordlist loads, and the permutation pass is a second scan after
// the main one.

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

// summarize adds the pass to the target's summary with the command line's
// code (#298, #347). errText is the scan's first error, if any.
func (p *permutationPass) summarize(t *output.TargetSummary, interrupted bool, errText string) {
	if p == nil {
		return
	}
	pass := report.PermutationPass{Seeds: p.seeds, Candidates: p.candidates, Found: p.found, Failure: errText}
	if p.done {
		pass.Final = &p.final
	}
	report.Permutation(t, pass, interrupted, settingLabel)
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
// goroutine, with the command line's code (#347). The seeds are the names the
// main pass found and the ones the sources proposed; candidates that are
// entries or seeds already are left out, so nothing is queried twice, and no
// map as large as the wordlist is built (#321).
func permutationCmd(domain string, entries, found []string, cands *candidates.Set) tea.Cmd {
	return func() tea.Msg {
		var seeds map[string]struct{}
		if cands != nil {
			seeds = cands.Seeds()
		}
		rel := candidates.RelativeSeeds(domain, found, seeds)
		if len(rel) == 0 {
			return permutationReadyMsg{}
		}
		perms, tooLong := candidates.Permutations(domain, entries, rel)
		return permutationReadyMsg{seeds: len(rel), candidates: perms, tooLong: tooLong}
	}
}
