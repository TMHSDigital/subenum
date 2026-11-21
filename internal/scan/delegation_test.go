package scan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// delegationZone serves example.com with subzones whose every name server
// is gone (old, old2), one delegated to a name server that exists (lame),
// and www. Asked to recurse, as a resolver would, a gone subzone is
// SERVFAIL; asked without recursion, as the zone's own server, it is a
// referral. tcpOnly makes the referrals arrive truncated over UDP.
func delegationZone(t *testing.T, tcpOnly bool) *dnstest.Server {
	t.Helper()
	return dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "example.com":
			return dnstest.Reply{}
		case "www.example.com":
			return dnstest.Reply{A: []string{"192.0.2.10"}}
		case "ns.example.com":
			return dnstest.Reply{A: []string{"192.0.2.53"}}
		case "old.example.com", "old2.example.com", "lame.example.com":
			if q.Recursive {
				return dnstest.ServFail
			}
			host := "ns1.gone.example.net"
			if q.Name == "lame.example.com" {
				host = "ns.example.com"
			}
			return dnstest.Reply{Referral: []string{host}, Truncate: tcpOnly && !q.TCP}
		}
		return dnstest.NXDomain
	})
}

// runDelegationScan scans entries of example.com on srv and returns the
// takeover hint of each result, the notices and the final stats.
func runDelegationScan(t *testing.T, srv *dnstest.Server, cfg Config) (map[string]string, map[string][]dns.Record, []string, Stats) {
	t.Helper()
	cfg.Domain, cfg.Concurrency, cfg.Attempts = "example.com", 1, 1
	cfg.Timeout = 2 * time.Second
	cfg.DNSServer, cfg.Resolver = srv.Addr, dns.NewResolver(2*time.Second, srv.Addr)
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	hints, records := map[string]string{}, map[string][]dns.Record{}
	var notices []string
	var stats Stats
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			hints[ev.Result.Subdomain] = ev.Result.Takeover
			records[ev.Result.Subdomain] = ev.Result.Records
		case EventNotice:
			notices = append(notices, ev.Message)
		case EventError:
			t.Fatalf("error: %s", ev.Message)
		case EventDone:
			stats = ev.Stats
		}
	}
	return hints, records, notices, stats
}

// TestDanglingDelegationAtParent covers #406: under NS, a name that ends
// SERVFAIL is asked of the zone's name servers without recursion; one
// delegated only to name servers that do not exist is reported with its
// referral's NS records and flagged dangling-ns, while one whose name
// server exists stays inconclusive. The checks are counted in the stats and
// in QueriesSent.
func TestDanglingDelegationAtParent(t *testing.T) {
	srv := delegationZone(t, false)
	hints, records, _, st := runDelegationScan(t, srv, Config{
		Entries: []string{"www", "old", "lame", "missing"}, Types: []string{"A", "NS"}, ZoneServer: srv.Addr,
	})
	if hints["old.example.com"] != dns.DanglingNS {
		t.Errorf("old.example.com hint = %q (results %v), want %s", hints["old.example.com"], hints, dns.DanglingNS)
	}
	if want := []dns.Record{{Type: "NS", Value: "ns1.gone.example.net"}}; len(records["old.example.com"]) != 1 || records["old.example.com"][0] != want[0] {
		t.Errorf("old.example.com records = %v, want %v", records["old.example.com"], want)
	}
	if _, ok := hints["lame.example.com"]; ok {
		t.Error("lame.example.com, delegated to a name server that exists, was reported")
	}
	if st.Found != 2 || st.Other != 1 || st.Takeover != 1 {
		t.Errorf("found %d, other %d, takeover %d; want 2, 1, 1", st.Found, st.Other, st.Takeover)
	}
	if st.ParentChecks != 2 || st.ParentQueries != 2 {
		t.Errorf("parent checks %d, queries %d; want 2 and 2 (old and lame)", st.ParentChecks, st.ParentQueries)
	}
	if st.QueriesSent < srv.Queries() {
		t.Errorf("QueriesSent %d, but the server saw %d", st.QueriesSent, srv.Queries())
	}
}

// TestDelegationCheckNeedsNS covers #406: without NS among the types, a
// SERVFAIL name is not checked at the zone's name servers.
func TestDelegationCheckNeedsNS(t *testing.T) {
	srv := delegationZone(t, false)
	hints, _, _, st := runDelegationScan(t, srv, Config{Entries: []string{"old"}, Types: []string{"A"}, ZoneServer: srv.Addr})
	if len(hints) != 0 || st.Other != 1 || st.ParentChecks != 0 || st.ParentQueries != 0 {
		t.Errorf("results %v, other %d, parent checks %d, queries %d; want none, 1, 0, 0", hints, st.Other, st.ParentChecks, st.ParentQueries)
	}
}

// TestDelegationCheckMaxQueries covers #406: the checks stop at
// -max-queries. Each check here takes two queries (the UDP referral is
// truncated), so with a budget of two only the first name is checked.
func TestDelegationCheckMaxQueries(t *testing.T) {
	srv := delegationZone(t, true)
	hints, _, _, st := runDelegationScan(t, srv, Config{
		Entries: []string{"old", "old2"}, Types: []string{"NS"}, ZoneServer: srv.Addr, MaxQueries: 2,
	})
	if hints["old.example.com"] != dns.DanglingNS {
		t.Errorf("results %v, want old.example.com flagged", hints)
	}
	if _, ok := hints["old2.example.com"]; ok || st.Other != 1 {
		t.Errorf("old2.example.com was checked past the budget (results %v, other %d)", hints, st.Other)
	}
	if st.ParentChecks != 1 || st.ParentQueries != 2 {
		t.Errorf("parent checks %d, queries %d; want 1 and 2", st.ParentChecks, st.ParentQueries)
	}
}

// TestDelegationCheckWithoutNameServers covers #406: when the zone's name
// servers cannot be found, the scan says so once and goes on, with the NS
// lookup counted.
func TestDelegationCheckWithoutNameServers(t *testing.T) {
	srv := delegationZone(t, false)
	hints, _, notices, st := runDelegationScan(t, srv, Config{Entries: []string{"old", "old2"}, Types: []string{"NS"}})
	if len(hints) != 0 || st.Other != 2 {
		t.Errorf("results %v, other %d; want none and 2", hints, st.Other)
	}
	n := 0
	for _, msg := range notices {
		if strings.Contains(msg, "no name servers found for example.com") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("notices %q, want one saying no name servers were found", notices)
	}
	if st.ParentQueries != 1 || st.ParentChecks != 0 {
		t.Errorf("parent checks %d, queries %d; want 0 and 1 (the NS lookup)", st.ParentChecks, st.ParentQueries)
	}
}
