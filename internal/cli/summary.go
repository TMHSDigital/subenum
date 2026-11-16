package cli

import (
	"time"

	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/report"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// buildSummary assembles the run-quality report (#70) from each target's
// status and result. The overall verdict is the worst target verdict.
func buildSummary(s *session, elapsed time.Duration) output.Summary {
	f := s.f
	sum := report.New(report.Run{
		Version:   resolveVersion(),
		Started:   s.started,
		Simulated: f.testMode,
		Seed:      f.seed,
		Resolver:  f.dnsServer,
		Zone:      f.simZone,
		RateLimit: f.rate,
	})
	summaries := make([]output.TargetSummary, 0, len(s.targets))
	for i, domain := range s.targets {
		summaries = append(summaries, targetSummary(domain, s.status[i], s.results[i]))
	}
	report.Finish(&sum, summaries, elapsed)
	if s.in.pool != nil {
		sum.Resolvers = s.in.pool.Stats()
	}
	return sum
}

func targetSummary(domain string, status report.Status, res targetResult) output.TargetSummary {
	t := report.Target(domain, status, res.err, res.done, res.final, scan.FlagName)
	ct := sourceByName(res.sources, "ct")
	t.CTNames, t.CTError = len(ct.names), ct.err
	for _, src := range res.sources {
		t.Sources = append(t.Sources, output.SourceSummary{Name: src.source, Names: len(src.names), Found: res.foundBy[src.source], Error: src.err, Truncated: src.truncated != ""})
	}
	t.AXFRAllowed, t.AXFRNames, t.AXFRError = res.axfr.allowed, len(res.axfr.names), res.axfr.err
	t.AXFRFound = res.foundBy[candidates.AXFR]
	t.ZoneDenial = string(res.axfr.denial)
	t.QueriesSent += res.axfr.queries // the NS and address lookups and the transfers (#85)
	if p := res.permutation; p != nil && res.done && status != report.StatusNotRun && status != report.StatusSkipped {
		pass := report.PermutationPass{Seeds: p.seeds, Candidates: p.candidates, Found: p.found, Failure: p.pass.err}
		if p.pass.done {
			pass.Final = &p.pass.final
		}
		report.Permutation(&t, pass, status == report.StatusInterrupted, scan.FlagName)
	}
	return t
}
