package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// parseSummary reads a -stats file, or finds the summary line at the end
// of jsonl output.
func parseSummary(text string) (output.Summary, error) {
	var s output.Summary
	if json.Unmarshal([]byte(text), &s) == nil && s.Type == "summary" {
		return s, nil
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		s = output.Summary{}
		if json.Unmarshal([]byte(strings.TrimSpace(lines[i])), &s) == nil && s.Type == "summary" {
			return s, nil
		}
	}
	return s, errors.New(`stats is not a subenum run-quality report: expected JSON with "type": "summary", as -stats writes`)
}

// verdictMeaning says what each verdict lets the reader conclude.
var verdictMeaning = map[string]string{
	scan.VerdictComplete:   "the results can be trusted, and a name missing from them most likely does not exist",
	scan.VerdictDegraded:   "the results are usable, but some names were not tested or got no answer, so a missing name may still exist",
	scan.VerdictUnreliable: "too many lookups failed: a missing name means nothing, and the scan should be repeated",
}

func explainSummary(s output.Summary) string {
	var b strings.Builder
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(&b, format+"\n", a...) }
	p("Overall verdict: %s (%s).", s.Verdict, s.Reason)
	if m := verdictMeaning[s.Verdict]; m != "" {
		p("That means %s.", m)
	}
	switch {
	case s.Simulated:
		p("This was a simulated run (-simulate): the results are invented and no DNS query was sent.")
	case s.Zone != "":
		p("This was a lab run: answers came from the scenario %s on a local DNS server.", s.Zone)
	}
	if !s.Simulated {
		rate := "no rate limit"
		if s.RateLimit > 0 {
			rate = fmt.Sprintf("a limit of %d per second", s.RateLimit)
		}
		p("%d DNS queries went to %s in %.1fs, %.0f per second against %s.", s.QueriesSent, s.Resolver, float64(s.DurationMs)/1000, s.AchievedQPS, rate)
	}
	for _, t := range s.Targets {
		p("")
		explainTarget(p, t)
	}
	if s.Diff != nil {
		p("")
		p("Compared with %s: %d added, %d removed, %d changed.", s.Diff.Previous, s.Diff.Added, s.Diff.Removed, s.Diff.Changed)
		if s.Diff.Unverified > 0 {
			p("%d earlier names could not be checked, so they are not counted as removed.", s.Diff.Unverified)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func explainTarget(p func(string, ...any), t output.TargetSummary) {
	o := t.Outcomes
	p("%s: %s, verdict %s (%s).", t.Domain, t.Status, t.Verdict, t.Reason)
	if t.Error != "" {
		p("  Error: %s", t.Error)
	}
	p("  %d of %d candidate names tested, %d found. Outcomes: %d resolved, %d do not exist, %d timed out, %d refused, %d other failures, %d matched the wildcard.",
		t.Processed, t.Total, t.Found, o.Resolved, o.NXDomain, o.Timeout, o.Refused, o.Other, o.WildcardFiltered)
	failed := o.Timeout + o.Refused + o.Other
	switch {
	case t.Verdict == scan.VerdictUnreliable:
		p("  Next time: lower -rate or add -auto-rate, try another -dns-server, and rerun; -retry-inconclusive retries the %d names without an answer.", failed)
	case failed > 0:
		p("  %d names got no answer; -retry-inconclusive looks them up again at the end of the scan.", failed)
	}
	if t.SkippedCap > 0 {
		// A run that ends on -max-queries writes no resume state, so -resume
		// is not offered for it (#320). The command line saves one when
		// -max-duration runs out (#294); this server's scans never do.
		if t.StoppedBy == "duration" {
			p("  %d names were not tested because -max-duration ran out; raise it and run the scan again, or continue a command-line run with subenum -resume and the state file it saved.", t.SkippedCap)
		} else {
			p("  %d names were not tested because -max-queries ran out; raise it and run the scan again.", t.SkippedCap)
		}
	}
	if t.Wildcard {
		p("  The domain answers every name (a wildcard), so subenum dropped %d answers matching the wildcard; a real name that answers the same way is dropped too.", o.WildcardFiltered)
	}
	if t.Takeover > 0 {
		p("  %d results have a subdomain-takeover hint: leads to verify by hand, not findings.", t.Takeover)
	}
	if t.Internal > 0 {
		p("  %d public names answer with internal (private, loopback or similar) addresses.", t.Internal)
	}
	if len(t.AXFRAllowed) > 0 {
		p("  Zone transfer (AXFR) was allowed by %s: anyone can list the zone, a misconfiguration to fix.", strings.Join(t.AXFRAllowed, ", "))
	}
	if t.ZoneDenial == "nsec" {
		p("  The zone is signed with plain NSEC, so every name in it can be listed by walking the chain.")
	}
	for _, src := range t.Sources {
		if src.Error != "" {
			p("  Passive source %s failed (%s); the scan went on without it.", src.Name, src.Error)
		}
		if src.Truncated {
			p("  Passive source %s stopped at one of its limits: its %d names were scanned, but some hosts may be missing.", src.Name, src.Names)
		}
	}
	if pm := t.Permutation; pm != nil {
		if pm.Verdict == "" {
			p("  Permutation pass: %d candidates from %d seeds, %d found.", pm.Candidates, pm.Seeds, pm.Found)
		} else {
			p("  Permutation pass: %d candidates from %d seeds, %d tested with %d queries, %d found; its own verdict %s.",
				pm.Candidates, pm.Seeds, pm.Processed, pm.QueriesSent, pm.Found, pm.Verdict)
		}
		// Since #298 the pass's verdict becomes the target's when it is worse.
		if strings.HasPrefix(t.Reason, permutationReason) {
			p("  The permutation pass set this target's verdict: it went worse than the main pass, so its outcome is the one to act on.")
		}
	}
}
