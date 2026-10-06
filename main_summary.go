package main

import (
	"time"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/report"
)

// buildSummary assembles the run-quality report (#70) from each target's
// status and result. The overall verdict is the worst target verdict.
func buildSummary(f cliFlags, targets, status []string, results []targetResult, started time.Time, elapsed time.Duration) output.Summary {
	s := report.New(report.Run{
		Version:   resolveVersion(),
		Started:   started,
		Simulated: f.testMode,
		Seed:      f.seed,
		Resolver:  f.dnsServer,
		Zone:      f.simZone,
		RateLimit: f.rate,
	})
	summaries := make([]output.TargetSummary, 0, len(targets))
	for i, domain := range targets {
		summaries = append(summaries, targetSummary(domain, status[i], results[i]))
	}
	report.Finish(&s, summaries, elapsed)
	if f.pool != nil {
		s.Resolvers = f.pool.Stats()
	}
	return s
}

func targetSummary(domain, status string, res targetResult) output.TargetSummary {
	t := report.Target(domain, status, res.err, res.done, res.final)
	t.CTNames, t.CTError = len(res.ct.names), res.ct.err
	if p := res.permutation; p != nil && res.done && status != "" && status != "skipped" {
		t.Permutation = &output.PermutationSummary{Seeds: p.seeds, Candidates: p.candidates, Found: p.found}
		if p.pass.done {
			t.Permutation.Verdict, _ = p.pass.final.Stats.Verdict(status == "interrupted")
		}
	}
	return t
}
