package scan

import (
	"context"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// TestFollowTargets covers #432: CNAME, MX, NS and HTTPS (#438) values
// under the target are followed, once each; the target itself, names
// outside it, excluded names, other record types and an HTTPS "." target
// are not.
func TestFollowTargets(t *testing.T) {
	cfg := Config{Domain: "example.com", scope: newScope([]string{"*.corp.example.com"})}
	got := followTargets(cfg, []dns.Record{
		{Type: "CNAME", Value: "LB-7.Int.example.com."},
		{Type: "MX", Value: "10 mx1.example.com"},
		{Type: "NS", Value: "ns1.example.com"},
		{Type: "NS", Value: "ns1.example.com"},
		{Type: "CNAME", Value: "cdn.example.net"},
		{Type: "CNAME", Value: "example.com"},
		{Type: "CNAME", Value: "vpn.corp.example.com"},
		{Type: "TXT", Value: "x.example.com"},
		{Type: "A", Value: "192.0.2.1"},
		{Type: "HTTPS", Value: "0 edge.example.com"},        // AliasMode (#438)
		{Type: "HTTPS", Value: "1 alt.example.com alpn=h2"}, // ServiceMode
		{Type: "HTTPS", Value: "1 . alpn=h2,h3 port=443"},   // the name itself
		{Type: "HTTPS", Value: "0 edge.cdn.example.net"},    // outside the target
	})
	want := []string{"lb-7.int.example.com", "mx1.example.com", "ns1.example.com", "edge.example.com", "alt.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("targets %v, want %v", got, want)
	}
}

// TestDispatcherFollow covers #432: a target is queued once, before the
// remaining candidates, and not when the scan tests it anyway as an entry
// or as a child of a queued parent; past a budget it is counted as skipped.
func TestDispatcherFollow(t *testing.T) {
	d := testDispatcher(Config{Entries: []string{"www", "api"}, RecursiveEntries: []string{"x"}, Recursive: true, FollowRecords: true}, 2)
	if j, _ := d.next(); j.domain != "www.example.com" {
		t.Fatalf("first job %s", j.domain)
	}
	d.expand(job{domain: "www.example.com", depth: 1})
	d.follow([]string{"lb.example.com", "api.example.com", "x.www.example.com", "lb.example.com"})
	if d.remaining != 1+1+1 { // api, x.www, lb
		t.Errorf("remaining %d, want 3", d.remaining)
	}
	j, _ := d.next()
	if j.domain != "lb.example.com" || !j.followed || j.root != -1 {
		t.Errorf("next job %+v, want the followed lb.example.com", j)
	}
	if got := drain(d); !slices.Equal(got, []string{"api.example.com", "x.www.example.com"}) {
		t.Errorf("rest %v", got)
	}
	d.follow([]string{"lb.example.com"}) // already tested
	if d.remaining != 0 {
		t.Errorf("a target tested once was queued again")
	}

	// A recursion candidate already followed is not generated again.
	d = testDispatcher(Config{Entries: []string{"www"}, Recursive: true, FollowRecords: true}, 2)
	d.follow([]string{"www.www.example.com"})
	d.expand(job{domain: "www.example.com", depth: 1})
	if got := drain(d); !slices.Equal(got, []string{"www.www.example.com", "www.example.com"}) {
		t.Errorf("followed then expanded: %v", got)
	}

	// Past the budget the queue and later targets are skipped.
	d = testDispatcher(Config{Entries: []string{"www"}, FollowRecords: true, MaxQueries: 1}, 1)
	d.follow([]string{"a.example.com", "b.example.com"})
	drain(d)
	d.follow([]string{"c.example.com"})
	if d.admitted != 1 || d.skipped != 3 || d.remaining != 0 {
		t.Errorf("admitted %d skipped %d remaining %d, want 1, 3 and 0", d.admitted, d.skipped, d.remaining)
	}
}

// TestRunFollowRecords covers #432 end to end: a name only a CNAME names is
// found with FollowRecords, and so is its own CNAME target; without
// FollowRecords neither is.
func TestRunFollowRecords(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "example.com":
			return dnstest.Reply{}
		case "app.example.com":
			return dnstest.Reply{CNAME: "lb-7.int.example.com", A: []string{"192.0.2.7"}}
		case "lb-7.int.example.com":
			return dnstest.Reply{CNAME: "edge.example.com", A: []string{"192.0.2.7"}}
		case "edge.example.com":
			return dnstest.Reply{A: []string{"192.0.2.7"}}
		}
		return dnstest.NXDomain
	})
	addr := srv.Addr
	run := func(follow bool) map[string]bool {
		cfg := Config{
			Domain: "example.com", Entries: []string{"app", "www"},
			Concurrency: 2, Timeout: time.Second, Attempts: 1, Types: []string{"A", "CNAME"},
			FollowRecords: follow, Exclude: []string{"vpn.example.com"},
			Resolver: dns.NewResolver(time.Second, addr), DNSServer: addr,
		}
		found := map[string]bool{}
		events := make(chan Event, 64)
		go Run(context.Background(), cfg, events)
		for ev := range events {
			if ev.Kind == EventResult {
				found[ev.Result.Subdomain] = true
				if ev.Followed != (ev.Result.Subdomain != "app.example.com") {
					t.Errorf("%s: Followed %v", ev.Result.Subdomain, ev.Followed)
				}
			}
		}
		return found
	}
	if got, want := run(true), map[string]bool{"app.example.com": true, "lb-7.int.example.com": true, "edge.example.com": true}; !maps.Equal(got, want) {
		t.Errorf("FollowRecords found %v, want %v", got, want)
	}
	if got := run(false); !maps.Equal(got, map[string]bool{"app.example.com": true}) {
		t.Errorf("without FollowRecords found %v", got)
	}
}
