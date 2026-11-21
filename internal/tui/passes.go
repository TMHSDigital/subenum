package tui

import (
	"context"
	"fmt"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/TMHSDigital/subenum/internal/axfr"
	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/dns"
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
	passive.Lookup
	added int // names that were not candidates already
}

// fetchSources asks every source for the domain's names at once, with the
// command line's code (#355). A failed lookup is reported on the scan
// screen; the scan goes on without its names.
func fetchSources(ctx context.Context, domain string, sources []string, o Options) []sourceLookup {
	opts := passive.Options{
		UserAgent: passive.UserAgent("subenum/" + o.Version),
		BaseURLs:  o.SourceURLs,
	}
	// The form admitted only known names.
	lookups := passive.FetchAll(ctx, sources, opts, domain)
	res := make([]sourceLookup, len(lookups))
	for i, l := range lookups {
		res[i].Lookup = l
	}
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
		perms, tooLong, _ := candidates.Permutations(domain, entries, rel)
		return permutationReadyMsg{seeds: len(rel), candidates: perms, tooLong: tooLong}
	}
}

// zoneAnswer is what the Zone Transfer and NSEC Walk fields got from the
// domain's name servers before the scan (#418).
type zoneAnswer struct {
	axfr.Result
	notes     []string // the attempt's findings and warnings, for the scan screen
	addedAXFR int      // transferred names that were not candidates already
	addedNSEC int      // walked names that were not candidates already
}

// askZone asks the domain's name servers for a zone transfer, walks a
// plain-NSEC zone, or both, with the command line's code and bounds (#418).
// Name servers and names out of scope are neither asked nor returned (#372);
// the walk is paced by Rate, sends at most Max Queries and stops at
// deadline (zero for none).
func askZone(ctx context.Context, vals formValues, o Options, deadline time.Time) zoneAnswer {
	var z zoneAnswer
	var mu sync.Mutex
	info := func(format string, a ...any) {
		mu.Lock()
		z.notes = append(z.notes, fmt.Sprintf(format, a...))
		mu.Unlock()
	}
	skip := scan.Excluder(vals.Exclude)
	opts := axfr.Options{
		Resolver:   vals.DNSServer,
		Port:       o.TransferPort,
		Timeout:    vals.Timeout,
		Info:       info,
		Skip:       skip,
		NoTransfer: !vals.axfr,
	}
	if vals.nsecWalk {
		opts.Walk = &dns.WalkOptions{
			Timeout:    vals.Timeout,
			MaxQueries: vals.MaxQueries,
			Limiter:    dns.NewRateLimiter(vals.Rate),
			Deadline:   deadline,
			Skip:       skip,
		}
	}
	r := axfr.Try(ctx, vals.Domain, opts)
	mu.Lock()
	defer mu.Unlock()
	z.Result = r
	if r.Err != "" {
		without := "a zone transfer"
		switch {
		case !vals.axfr:
			without = "an NSEC walk"
		case vals.nsecWalk:
			without = "a zone transfer or an NSEC walk"
		}
		z.notes = append(z.notes, fmt.Sprintf("Warning: %s; scanning %s without %s", r.Err, vals.Domain, without))
	}
	return z
}
