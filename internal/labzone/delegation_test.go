package labzone

import (
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"golang.org/x/net/dns/dnsmessage"
)

// TestDanglingDelegation covers #406: a subzone none of whose name servers
// has an address in the scenario answers a recursive query SERVFAIL, as a
// resolver that cannot reach them does, and a non-recursive one with a
// referral, as the parent zone's server does; names under it too. A
// delegation with a name server that answers is served from the scenario as
// before, and so is the apex's own NS.
func TestDanglingDelegation(t *testing.T) {
	z := mustParse(t, strings.Join([]string{
		"$DNSSEC nsec",
		"@        NS  ns1",
		"ns1      A   192.0.2.53",
		"old      NS  ns1.gone.example.",
		"old      NS  ns2.old",
		"ok       NS  ns1",
		"glued    NS  ns1.glued",
		"ns1.glued A  192.0.2.54",
	}, "\n"))
	h := z.Handler([]string{"lab.example"})
	ask := func(name string, qtype dnsmessage.Type, recursive bool) dnsserver.Reply {
		return h(dnsserver.Query{Name: name, Type: qtype, Recursive: recursive})
	}
	wantRef := []string{"ns1.gone.example", "ns2.old.lab.example"}
	for _, name := range []string{"old.lab.example", "www.old.lab.example"} {
		for _, qt := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeNS} {
			if r := ask(name, qt, true); r.RCode != dnsmessage.RCodeServerFailure {
				t.Errorf("recursive %s %v: %+v, want SERVFAIL", name, qt, r)
			}
			r := ask(name, qt, false)
			if r.RCode != dnsmessage.RCodeSuccess || !slices.Equal(r.Referral, wantRef) || r.ReferralZone != "old.lab.example" || len(r.NSEC) > 0 {
				t.Errorf("non-recursive %s %v: %+v, want a referral to %v", name, qt, r, wantRef)
			}
		}
	}
	for _, name := range []string{"ok.lab.example", "glued.lab.example"} {
		for _, recursive := range []bool{true, false} {
			if r := ask(name, dnsmessage.TypeNS, recursive); len(r.NS) != 1 || r.Referral != nil {
				t.Errorf("%s (recursive %v): %+v, want its NS answered", name, recursive, r)
			}
		}
	}
	if r := ask("lab.example", dnsmessage.TypeNS, true); !slices.Equal(r.NS, []string{"ns1.lab.example"}) {
		t.Errorf("apex NS: %+v", r)
	}
	if r := ask("lab.example", dnsmessage.TypeAXFR, false); r.RCode != dnsmessage.RCodeRefused {
		t.Errorf("AXFR: %+v, want refused", r)
	}
}
