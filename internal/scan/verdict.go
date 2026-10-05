package scan

import "fmt"

// Run-quality verdicts, from best to worst (#70).
const (
	VerdictComplete   = "complete"   // every candidate got a definitive answer, or nearly so
	VerdictDegraded   = "degraded"   // usable, but some candidates are unknown
	VerdictUnreliable = "unreliable" // too many failures to trust the absence of a name
)

// degradedFailPercent is the share of failed lookups at which a finished scan
// is degraded. Above reliabilityFailPercent it is unreliable, the same line
// the reliability guard aborts at.
const degradedFailPercent = 1

// VerdictRank orders verdicts so the worst of several can be picked.
func VerdictRank(v string) int {
	switch v {
	case VerdictComplete:
		return 0
	case VerdictDegraded:
		return 1
	}
	return 2
}

// Verdict grades a scan that reached EventDone. interrupted is set when the
// user stopped it (Ctrl+C, SIGTERM), which Stats cannot know.
func (s Stats) Verdict(interrupted bool) (verdict, reason string) {
	processed := s.Sum()
	fails := s.failures()
	detail := fmt.Sprintf("%d of %d lookups failed (timeout %d, refused %d, other %d)",
		fails, processed, s.Timeout, s.Refused, s.Other)
	switch {
	case s.Aborted:
		return VerdictUnreliable, "the reliability guard aborted the scan: " + detail
	case processed > 0 && fails*100 > processed*reliabilityFailPercent:
		return VerdictUnreliable, detail
	case interrupted:
		return VerdictDegraded, fmt.Sprintf("interrupted after %d lookups", processed)
	case fails > 0 && fails*100 >= processed*degradedFailPercent:
		return VerdictDegraded, detail
	case s.Skipped > 0:
		return VerdictDegraded, fmt.Sprintf("-max-queries reached; %d candidates not tested", s.Skipped)
	case fails > 0:
		return VerdictComplete, detail + ", under 1%"
	}
	return VerdictComplete, fmt.Sprintf("all %d lookups got a definitive answer", processed)
}
