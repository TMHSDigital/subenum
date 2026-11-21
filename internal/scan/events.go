package scan

import (
	"github.com/TMHSDigital/subenum/internal/dns"
)

// EventKind categorises a scan event.
type EventKind int

// Event kinds.
const (
	// EventResult reports a resolved subdomain.
	EventResult   EventKind = iota
	EventProgress           // progress update
	EventNotice             // informational notice; see Event.Notice
	// EventError reports a problem. Usually the scan then stops and its
	// EventDone has Stopped set; after the reliability guard (with NoAbort)
	// the scan goes on. Event.Fatal tells the two apart.
	EventError
	// EventDone is always the last event, sent exactly once (#99).
	EventDone
)

// NoticeKind says what an EventNotice is about, so consumers can style or
// filter notices without parsing the message (#68).
type NoticeKind int

// Notice kinds.
const (
	// NoticeWildcard means wildcard DNS was detected, or its check failed
	// under -force.
	NoticeWildcard NoticeKind = iota + 1
	NoticeCap                 // -max-queries or -max-duration reached; candidates skipped
	NoticeCeiling             // recursive scan may generate very many queries
	NoticeSkip                // a recursive branch was not expanded, or a check could not be made (#406)
	NoticeRate                // AutoRate changed the query rate (#220)
)

// String names a notice kind for structured output.
func (k NoticeKind) String() string {
	switch k {
	case NoticeWildcard:
		return "wildcard"
	case NoticeCap:
		return "cap"
	case NoticeCeiling:
		return "ceiling"
	case NoticeSkip:
		return "skip"
	case NoticeRate:
		return "rate"
	}
	return "notice"
}

// Result is one resolved subdomain. It is the single per-result type that
// flows from the engine (Event.Result) to the writers, which embed it in
// output.Result (#162), so its JSON tags and field order are part of the
// structured output formats: change them only together with those formats.
type Result struct {
	Subdomain string       `json:"subdomain"`
	Records   []dns.Record `json:"records"` // of the looked-up types
	// Simulated is set on every result of a simulated scan, so invented
	// names can never pass for real recon output once saved or piped (#53).
	Simulated bool `json:"simulated,omitempty"`
	// Takeover is a DNS-only subdomain-takeover hint ("dangling",
	// "provider:<name>" or "dangling:<name>"), see dns.TakeoverHint;
	// verify it by hand (#71).
	Takeover string `json:"takeover_candidate,omitempty"`
	// Internal is the most notable non-public scope among the name's
	// addresses ("loopback", "unspecified", "link-local", "private" or
	// "cgnat"), see dns.InternalScope; empty when every address is public.
	// A public name that answers with one leaks internal addressing (#218).
	Internal string `json:"internal_address,omitempty"`
	// Partial is set when a requested record type's lookup failed (timeout,
	// refusal or other error) on every attempt while another type answered:
	// Records may lack records of the failed type (#357).
	Partial bool `json:"partial,omitempty"`
}

// Event is emitted on the events channel during a scan.
type Event struct {
	Kind      EventKind
	Notice    NoticeKind // EventNotice: what the notice is about
	Result    Result     // EventResult: the resolved subdomain and its records
	Processed int64      // EventProgress
	Total     int64      // EventProgress
	Found     int64      // EventProgress / EventDone
	Message   string     // EventError / EventNotice
	Stats     Stats      // EventDone: per-outcome counters
	// Stopped is set on EventDone when the scan ended before testing any
	// candidate: after an EventError (out of scope, recursion ceiling, failed
	// preflight or wildcard check, wildcard zone without Force) or when ctx
	// was cancelled during those checks. Its Stats cover only the checks.
	Stopped bool
	// Fatal is set on an EventError that ends the scan. The one error
	// without it is the reliability guard's warning under NoAbort (#308).
	Fatal bool
	// Failed is set on EventDone when the scan failed: a fatal EventError
	// was sent, or the reliability guard aborted the scan. A cancelled scan
	// has not failed. Consumers read this instead of working it out from
	// the errors they saw and their own copy of NoAbort (#308).
	Failed bool
	// Followed is set on an EventResult for a name a FollowRecords scan
	// tested because another result's CNAME, MX or NS record named it (#432).
	Followed bool
}
