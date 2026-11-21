package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/output"
)

// ptrZone answers a small example.com whose www and api addresses have PTR
// records: one names a host no wordlist holds, one a stale name, one a name
// outside the target and one an excluded name. It counts the queries for
// each name and type.
type ptrZone struct {
	mu   sync.Mutex
	seen map[string]int // "name/TYPE" -> queries
}

func (z *ptrZone) asked(name string, t dnsmessage.Type) int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.seen[name+"/"+t.String()]
}

func (z *ptrZone) ptrQueries() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	n := 0
	for k, v := range z.seen {
		if strings.HasSuffix(k, "/"+dnsmessage.TypePTR.String()) {
			n += v
		}
	}
	return n
}

func (z *ptrZone) answer(q dnstest.Query) dnstest.Reply {
	z.mu.Lock()
	z.seen[q.Name+"/"+q.Type.String()]++
	z.mu.Unlock()
	switch q.Name {
	case "example.com":
		return dnstest.Reply{}
	case "www.example.com":
		return dnstest.Reply{A: []string{"192.0.2.10"}}
	case "api.example.com":
		return dnstest.Reply{A: []string{"192.0.2.11"}}
	case "multi.example.com":
		return dnstest.Reply{A: []string{"192.0.2.10", "192.0.2.11"}}
	case "db.example.com":
		return dnstest.Reply{A: []string{"10.0.0.5"}} // private: never reverse-looked up
	case "host-12.dc1.example.com":
		return dnstest.Reply{A: []string{"192.0.2.10"}}
	case "10.2.0.192.in-addr.arpa":
		return dnstest.Reply{PTR: []string{"host-12.dc1.example.com", "stale-1.example.com", "other.example.net", "vpn.corp.example.com", "www.example.com"}}
	case "11.2.0.192.in-addr.arpa":
		return dnstest.Reply{PTR: []string{"api.example.com"}}
	}
	return dnstest.NXDomain
}

// TestE2EPTR covers #436's acceptance: with -ptr, a name reachable only
// through a PTR record is reported with source ptr after forward
// confirmation, a stale PTR name is not reported, and -stats counts the
// pass; private addresses and names or reverse zones -exclude rules out are
// never queried; -max-queries caps the PTR queries; without -ptr no PTR
// query is sent and the output is unchanged.
func TestE2EPTR(t *testing.T) {
	t.Parallel()
	z := &ptrZone{seen: map[string]int{}}
	srv := dnstest.Start(t, z.answer)
	wl := writeFile(t, "wl.txt", "www\napi\ndb\n")
	run := func(extra ...string) (map[string][]string, output.TargetSummary) {
		t.Helper()
		stats := filepath.Join(t.TempDir(), "run.json")
		args := append(localArgs(append([]string{"-dns-server", srv.Addr, "-type", "A", "-progress=false", "-format", "jsonl",
			"-w", wl, "-stats", stats, "-exclude", "*.corp.example.com"}, extra...)...), "example.com")
		code, out := runCLIWith(t, runArgs{args: args})
		if code != exitOK {
			t.Fatalf("exit %d\n%s", code, out)
		}
		sources := map[string][]string{}
		for name, r := range seenResults(t, out) {
			sources[name] = r.Sources
		}
		var s output.Summary
		b, err := os.ReadFile(stats)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		return sources, s.Targets[0]
	}

	plain, base := run()
	if len(plain) != 3 || base.PTRAddresses != 0 || base.PTRQueries != 0 {
		t.Errorf("without -ptr: results %v, ptr_addresses %d, ptr_queries %d", plain, base.PTRAddresses, base.PTRQueries)
	}
	if n := z.ptrQueries(); n != 0 {
		t.Fatalf("without -ptr, %d PTR queries were sent", n)
	}

	got, ts := run("-ptr")
	if !slices.Equal(got["host-12.dc1.example.com"], []string{"ptr"}) || len(got) != 4 {
		t.Errorf("-ptr: results %v, want the three wordlist names and host-12.dc1 with source ptr", got)
	}
	if _, ok := got["stale-1.example.com"]; ok {
		t.Error("a stale PTR name that does not resolve was reported")
	}
	if !slices.Equal(got["www.example.com"], []string{"wordlist"}) {
		t.Errorf("www sources %v: a name the main pass found keeps its source", got["www.example.com"])
	}
	// host-12.dc1 and stale-1: www and api were found, other.example.net is
	// outside the target and vpn.corp is excluded.
	if ts.PTRAddresses != 2 || ts.PTRNames != 2 || ts.PTRFound != 1 || ts.PTRQueries < 2 || ts.Verdict != "complete" {
		t.Errorf("-stats: ptr_addresses %d ptr_names %d ptr_found %d ptr_queries %d verdict %s",
			ts.PTRAddresses, ts.PTRNames, ts.PTRFound, ts.PTRQueries, ts.Verdict)
	}
	if ts.QueriesSent < base.QueriesSent+ts.PTRQueries+2 {
		t.Errorf("queries_sent %d does not include the %d PTR queries and the pass's lookups (%d without -ptr)", ts.QueriesSent, ts.PTRQueries, base.QueriesSent)
	}
	if z.asked("5.0.0.10.in-addr.arpa", dnsmessage.TypePTR) != 0 {
		t.Error("a private address was reverse-looked up")
	}
	if z.asked("vpn.corp.example.com", dnsmessage.TypeA) != 0 || z.asked("other.example.net", dnsmessage.TypeA) != 0 {
		t.Error("an excluded or off-target PTR name was looked up")
	}

	// An excluded reverse zone is never asked.
	before := z.ptrQueries()
	got, ts = run("-ptr", "-exclude", "*.corp.example.com,*.2.0.192.in-addr.arpa")
	if z.ptrQueries() != before || ts.PTRAddresses != 0 || len(got) != 3 {
		t.Errorf("excluded reverse zone: %d PTR queries, ptr_addresses %d, results %v", z.ptrQueries()-before, ts.PTRAddresses, got)
	}

	// -max-queries caps the PTR queries as it caps a pass's names.
	before = z.ptrQueries()
	_, ts = run("-ptr", "-max-queries", "1", "-w", writeFile(t, "multi.txt", "multi\n"))
	if n := z.ptrQueries() - before; n != 1 || ts.PTRAddresses != 1 {
		t.Errorf("-max-queries 1: %d PTR queries, ptr_addresses %d; want 1", n, ts.PTRAddresses)
	}
}

// TestPTRResume covers a resumed -ptr run (#436): a restored -ptr hit keeps
// its source, is not a -permute seed, and is not tested again.
func TestPTRResume(t *testing.T) {
	t.Parallel()
	z := &ptrZone{seen: map[string]int{}}
	srv := dnstest.Start(t, z.answer)
	wl := writeFile(t, "wl.txt", "www\n")
	args := append(localArgs("-dns-server", srv.Addr, "-type", "A", "-progress=false", "-format", "jsonl", "-w", wl, "-ptr"), "example.com")
	www := output.Result{Sources: []string{"wordlist"}}
	www.Subdomain, www.Records = "www.example.com", []dns.Record{{Type: "A", Value: "192.0.2.10"}}
	host := output.Result{Sources: []string{"ptr"}}
	host.Subdomain, host.Records = "host-12.dc1.example.com", []dns.Record{{Type: "A", Value: "192.0.2.10"}}
	path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{{Domain: "example.com", MainDone: true, RootDone: 1, Processed: 1, Total: 1,
		Results: []output.Result{www, host}}}})
	code, out := runCLIWith(t, runArgs{args: []string{"-resume", path}})
	got := seenResults(t, out)
	if code != exitOK || !slices.Equal(got["host-12.dc1.example.com"].Sources, []string{"ptr"}) || len(got) != 2 {
		t.Errorf("resumed: exit %d, results %v; want host-12.dc1 restored with source ptr\n%s", code, got, out)
	}
	if n := z.asked("host-12.dc1.example.com", dnsmessage.TypeA); n != 0 {
		t.Errorf("the restored -ptr hit was looked up %d times", n)
	}
	if names := mainPassNames([]output.Result{www, host}); !slices.Equal(names, []string{"www.example.com"}) {
		t.Errorf("mainPassNames = %v, want the -ptr hit left out of the -permute seeds", names)
	}
}

func TestPTRAddresses(t *testing.T) {
	t.Parallel()
	res := func(name string, recs ...dns.Record) output.Result {
		var r output.Result
		r.Subdomain, r.Records = name, recs
		return r
	}
	a := func(v string) dns.Record { return dns.Record{Type: "A", Value: v} }
	got := ptrAddresses([]output.Result{
		res("a.example.com", a("192.0.2.20"), a("10.1.2.3"), dns.Record{Type: "CNAME", Value: "x.example.com"}),
		res("b.example.com", a("192.0.2.3"), dns.Record{Type: "AAAA", Value: "2001:db8::1"}, a("127.0.0.1")),
		res("c.example.com", a("192.0.2.20"), a("198.51.100.9"), a("100.64.0.1")),
	}, []dns.Record{a("198.51.100.9")})
	want := []string{"192.0.2.3", "192.0.2.20", "2001:db8::1"}
	if !slices.Equal(got, want) {
		t.Errorf("ptrAddresses = %v, want %v (unique, public, sorted, no fingerprint)", got, want)
	}
}
