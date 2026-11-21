package scan

import (
	"sync/atomic"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// Stats is a snapshot of per-outcome query counters. Populated on EventDone.
//
// The CLI's -resume state file stores Stats as JSON, so the tags are a file
// format: they spell the field names as they were when the format was fixed,
// and renaming a field must keep its tag (or bump the state file's version)
// (#331).
type Stats struct {
	Found            int64 `json:"Found"`
	NXDomain         int64 `json:"NXDomain"`
	Timeout          int64 `json:"Timeout"`
	Refused          int64 `json:"Refused"`
	Other            int64 `json:"Other"`
	WildcardFiltered int64 `json:"WildcardFiltered"`

	// Run facts for the quality report (#70); not part of Sum.
	QueriesSent int64 `json:"QueriesSent"` // DNS queries dialed, retries included (0 when simulated)
	Skipped     int64 `json:"Skipped"`     // candidates not tested because -max-queries or -max-duration was reached
	Excluded    int64 `json:"Excluded"`    // candidates not tested because -exclude put them out of scope
	PoolHits    int64 `json:"PoolHits"`    // names a pool resolver said exist (-r)
	Confirmed   int64 `json:"Confirmed"`   // pool hits the trusted resolver confirmed
	Unconfirmed int64 `json:"Unconfirmed"` // pool hits the trusted resolver said do not exist
	Takeover    int64 `json:"Takeover"`    // results flagged as subdomain-takeover candidates
	Internal    int64 `json:"Internal"`    // results with a non-public address (Result.Internal, #218)
	Partial     int64 `json:"Partial"`     // found names a requested type's lookup failed for (Result.Partial, #357)
	// ParentChecks counts the names that ended SERVFAIL whose delegation was
	// asked of the zone's own name servers, and ParentQueries the queries
	// that took, the name server lookups included; QueriesSent counts them
	// too (#406).
	ParentChecks  int64 `json:"ParentChecks"`
	ParentQueries int64 `json:"ParentQueries"`
	// RootDone is the resume point: every wordlist entry before this index
	// has been fully looked up (#73). Entries at or after it may also be
	// done; resuming repeats at most one chunk (maxChunk jobs) per worker,
	// since workers report their jobs a chunk at a time (#184).
	RootDone    int64        `json:"RootDone"`
	Aborted     bool         `json:"Aborted"`     // the reliability guard cancelled the scan
	Expired     bool         `json:"Expired"`     // Deadline (-max-duration) stopped admission; Skipped counts what it left
	Wildcard    bool         `json:"Wildcard"`    // the root domain is a wildcard (scanned under -force)
	Fingerprint []dns.Record `json:"Fingerprint"` // final wildcard fingerprint, empty when none

	// Inconclusive lookups (#217). Retried counts the names the
	// RetryInconclusive pass looked up again, and Recovered the ones that
	// then got an answer: their first outcome (timeout, refused, other)
	// moves to the new one, so the outcome counters still add up to the
	// names tested. Inconclusive lists, sorted, the names whose lookup is
	// still a timeout, refusal or failure at the end of the scan; it is nil
	// without Config.ListInconclusive (#300).
	Retried      int64    `json:"Retried"`
	Recovered    int64    `json:"Recovered"`
	Inconclusive []string `json:"Inconclusive"`

	// AutoRate (#220): how many times the rate was halved, and the rate in
	// queries per second when the scan ended (0 = unlimited). Both are 0
	// without AutoRate.
	RateBackoffs int64 `json:"RateBackoffs"`
	FinalRate    int64 `json:"FinalRate"`

	// Repeat is the part of the counters above that a resume from RootDone
	// does again; not saved in the state file (#341).
	Repeat Repeat `json:"-"`
	// Pending lists, under Config.RetryInconclusive, the inconclusive names
	// the retry pass did not get to (the scan stopped first) and a resume
	// does not look up again anyway, for Config.RetryPrior of the resumed
	// scan (#315). The CLI saves it apart from Stats.
	Pending []Pending `json:"-"`
}

// Repeat counts the work of a scan that a resume from its RootDone repeats
// (#341): the wordlist entries at or past RootDone that were looked up or
// found out of scope (a chunk reported late, or names past a budget stop),
// and every lookup and exclusion below depth 1, since a resumed recursive
// scan expands every saved parent again. A stopped scan's counters, less
// these, plus the resumed scan's, count each name once.
type Repeat struct {
	Processed        int64 // lookups, wildcard-filtered ones included
	Found            int64
	NXDomain         int64
	Timeout          int64
	Refused          int64
	Other            int64
	WildcardFiltered int64
	Excluded         int64
	// Inconclusive lists the names of Stats.Inconclusive that are repeated.
	Inconclusive []string
}

// Repeat codes: how one name ended, for Stats.Repeat (#341).
const (
	repeatNone uint8 = iota
	repeatExcluded
	repeatWildcard
	repeatFound
	repeatNXDomain
	repeatTimeout
	repeatRefused
	repeatOther
	repeatCodes
)

// repeatCode is the repeat code of a lookup outcome.
func repeatCode(o dns.Outcome) uint8 {
	switch o {
	case dns.OutcomeFound:
		return repeatFound
	case dns.OutcomeNXDomain:
		return repeatNXDomain
	case dns.OutcomeTimeout:
		return repeatTimeout
	case dns.OutcomeRefused:
		return repeatRefused
	}
	return repeatOther
}

// Sum returns the number of classified queries (found + negatives + failures +
// wildcard-filtered).
func (s Stats) Sum() int64 {
	return s.Found + s.NXDomain + s.Timeout + s.Refused + s.Other + s.WildcardFiltered
}

func (s Stats) failures() int64 {
	return s.Timeout + s.Refused + s.Other
}

// AddCounts returns s with o's per-candidate counters added and o's
// Inconclusive names appended, for two scans reported as one (a resumed
// run's parts, a permutation pass after the main one). How the scan ended
// and where it stood (RootDone, Aborted, Expired, Wildcard, Fingerprint,
// FinalRate, Repeat, Pending) are left as s has them: the caller picks.
func (s Stats) AddCounts(o Stats) Stats {
	s.Found += o.Found
	s.NXDomain += o.NXDomain
	s.Timeout += o.Timeout
	s.Refused += o.Refused
	s.Other += o.Other
	s.WildcardFiltered += o.WildcardFiltered
	s.QueriesSent += o.QueriesSent
	s.Skipped += o.Skipped
	s.Excluded += o.Excluded
	s.PoolHits += o.PoolHits
	s.Confirmed += o.Confirmed
	s.Unconfirmed += o.Unconfirmed
	s.Takeover += o.Takeover
	s.Internal += o.Internal
	s.Partial += o.Partial
	s.ParentChecks += o.ParentChecks
	s.ParentQueries += o.ParentQueries
	s.Retried += o.Retried
	s.Recovered += o.Recovered
	s.Inconclusive = append(append([]string(nil), s.Inconclusive...), o.Inconclusive...)
	s.RateBackoffs += o.RateBackoffs
	return s
}

type counters struct {
	found            atomic.Int64
	nxdomain         atomic.Int64
	timeout          atomic.Int64
	refused          atomic.Int64
	other            atomic.Int64
	wildcardFiltered atomic.Int64
	skipped          atomic.Int64
	excluded         atomic.Int64
	poolHits         atomic.Int64
	confirmed        atomic.Int64
	unconfirmed      atomic.Int64
	takeover         atomic.Int64
	internal         atomic.Int64
	partial          atomic.Int64
	rootDone         atomic.Int64
	retried          atomic.Int64
	recovered        atomic.Int64
	aborted          atomic.Bool
	expired          atomic.Bool
}

func (c *counters) add(o dns.Outcome) { c.counter(o).Add(1) }

// counter is the outcome's counter; an unknown outcome counts as other.
func (c *counters) counter(o dns.Outcome) *atomic.Int64 {
	switch o {
	case dns.OutcomeFound:
		return &c.found
	case dns.OutcomeNXDomain:
		return &c.nxdomain
	case dns.OutcomeTimeout:
		return &c.timeout
	case dns.OutcomeRefused:
		return &c.refused
	}
	return &c.other
}

func (c *counters) snapshot() Stats {
	return Stats{
		Found:            c.found.Load(),
		NXDomain:         c.nxdomain.Load(),
		Timeout:          c.timeout.Load(),
		Refused:          c.refused.Load(),
		Other:            c.other.Load(),
		WildcardFiltered: c.wildcardFiltered.Load(),
		Skipped:          c.skipped.Load(),
		Excluded:         c.excluded.Load(),
		PoolHits:         c.poolHits.Load(),
		Confirmed:        c.confirmed.Load(),
		Unconfirmed:      c.unconfirmed.Load(),
		Takeover:         c.takeover.Load(),
		Internal:         c.internal.Load(),
		Partial:          c.partial.Load(),
		RootDone:         c.rootDone.Load(),
		Retried:          c.retried.Load(),
		Recovered:        c.recovered.Load(),
		Aborted:          c.aborted.Load(),
		Expired:          c.expired.Load(),
	}
}
