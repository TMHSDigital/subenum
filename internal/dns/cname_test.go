package dns

import (
	"context"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"golang.org/x/net/dns/dnsmessage"
)

// TestCNAMEOneQuery covers #249: -type CNAME sends one CNAME query a name,
// reads the alias from it, and maps each RCODE onto the outcome Go's
// LookupCNAME gave.
func TestCNAMEOneQuery(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "blog.example.com":
			return dnstest.Reply{CNAME: "ghost.example.net"}
		case "www.example.com":
			return dnstest.Reply{A: []string{"192.0.2.1"}} // NODATA for CNAME
		case "broken.example.com":
			return dnstest.ServFail
		case "busy.example.com":
			return dnstest.Refused
		case "big.example.com":
			return dnstest.Reply{CNAME: "edge.example.net", Truncate: true}
		}
		return dnstest.NXDomain
	})
	l := Lookup{Resolver: NewResolver(time.Second, srv.Addr), Timeout: time.Second, Attempts: 1, Types: []string{"CNAME"}}
	for _, tc := range []struct {
		name    string
		want    string // the CNAME target, if any
		outcome Outcome
		queries int64 // CNAME queries on the wire
	}{
		{"blog.example.com", "ghost.example.net", OutcomeFound, 1},
		{"www.example.com", "", OutcomeNXDomain, 1},
		{"nope.example.com", "", OutcomeNXDomain, 1},
		{"broken.example.com", "", OutcomeOther, 1},
		{"busy.example.com", "", OutcomeRefused, 1},
		{"big.example.com", "edge.example.net", OutcomeFound, 2}, // UDP, then TCP
	} {
		recs, outcome := l.Resolve(context.Background(), tc.name)
		if outcome != tc.outcome {
			t.Errorf("%s: outcome %v, want %v", tc.name, outcome, tc.outcome)
		}
		if tc.want != "" && (len(recs) != 1 || recs[0] != (Record{Type: "CNAME", Value: tc.want})) {
			t.Errorf("%s: records %v, want CNAME %s", tc.name, recs, tc.want)
		}
		for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			if n := srv.QueriesFor(tc.name, typ); n != 0 {
				t.Errorf("%s: %d %v queries; a CNAME lookup sends only CNAME", tc.name, n, typ)
			}
		}
		if n := srv.QueriesFor(tc.name, dnsmessage.TypeCNAME); n != tc.queries {
			t.Errorf("%s: %d CNAME queries, want %d", tc.name, n, tc.queries)
		}
	}
}

// TestCNAMETimeout: a server that never answers is a timeout, not a
// negative, and a cancelled scan is cancelled.
func TestCNAMETimeout(t *testing.T) {
	r := NewResolver(time.Second, startBlackHole(t))
	_, err := lookupType(contextWithTimeout(t, 100*time.Millisecond), r, "slow.example.com.", "slow.example.com", "CNAME")
	if Classify(err) != OutcomeTimeout {
		t.Errorf("unanswered CNAME query: %v (%v), want a timeout", err, Classify(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lookupType(ctx, r, "slow.example.com.", "slow.example.com", "CNAME"); Classify(err) != OutcomeCanceled {
		t.Errorf("cancelled CNAME lookup: %v (%v), want canceled", err, Classify(err))
	}
}

// TestCNAMEChain: the end of an alias chain in one answer is the target,
// as with Go's LookupCNAME.
func TestCNAMEChain(t *testing.T) {
	msg := dnsmessage.Message{Answers: []dnsmessage.Resource{
		cnameRR(t, "b.example.com.", "c.example.net."),
		cnameRR(t, "a.example.com.", "b.example.com."),
	}}
	if got := canonicalName(&msg, "A.example.com."); got != "c.example.net." {
		t.Errorf("canonicalName = %q, want c.example.net.", got)
	}
	if got := canonicalName(&dnsmessage.Message{}, "a.example.com."); got != "a.example.com." {
		t.Errorf("no alias: canonicalName = %q, want the name itself", got)
	}
	loop := dnsmessage.Message{Answers: []dnsmessage.Resource{
		cnameRR(t, "x.example.com.", "y.example.com."),
		cnameRR(t, "y.example.com.", "x.example.com."),
	}}
	_ = canonicalName(&loop, "x.example.com.") // must return, not spin
}

func cnameRR(t *testing.T, owner, target string) dnsmessage.Resource {
	t.Helper()
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)},
	}
}

func contextWithTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}
