package scan

import (
	"context"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// TestTakeoverHintRespectsExclude covers #316: the takeover hint never looks
// up a CNAME target or NS host that -exclude puts out of scope, still
// reports the provider match (which needs no query), and gives no dangling
// verdict for an excluded name. A target in scope is still checked.
func TestTakeoverHintRespectsExclude(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "www.example.com":
			return dnstest.Reply{CNAME: "vpn.example.com"}
		case "app.example.com":
			return dnstest.Reply{CNAME: "acme.herokuapp.com"}
		case "old.example.com":
			return dnstest.Reply{CNAME: "gone.example.net"}
		case "dev.example.com":
			if q.Type == dnsmessage.TypeNS {
				return dnstest.Reply{NS: []string{"ns.out.example"}}
			}
			return dnstest.Reply{}
		case "example.com":
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	cfg := Config{
		Domain: "example.com", Entries: []string{"www", "app", "old", "dev"}, Concurrency: 1,
		Timeout: 2 * time.Second, Attempts: 1, Types: []string{"CNAME", "NS"},
		Exclude:   []string{"vpn.example.com", "*.herokuapp.com", "ns.out.example"},
		DNSServer: srv.Addr, Resolver: dns.NewResolver(2*time.Second, srv.Addr),
	}
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	hints := map[string]string{}
	var errs []Event
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			hints[ev.Result.Subdomain] = ev.Result.Takeover
		case EventError:
			errs = append(errs, ev)
		}
	}
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	want := map[string]string{
		"www.example.com": "",                // excluded target: not looked up, so never dangling
		"app.example.com": "provider:heroku", // the provider match needs no query
		"old.example.com": "dangling",        // in scope: still checked
		"dev.example.com": "",                // excluded name server: not looked up
	}
	for name, hint := range want {
		got, ok := hints[name]
		if !ok {
			t.Errorf("%s not reported (results %v)", name, hints)
		} else if got != hint {
			t.Errorf("%s takeover hint = %q, want %q", name, got, hint)
		}
	}
	for _, name := range []string{"vpn.example.com", "acme.herokuapp.com", "ns.out.example"} {
		for _, qt := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			if n := srv.QueriesFor(name, qt); n != 0 {
				t.Errorf("%d %v queries for excluded %s, want 0", n, qt, name)
			}
		}
	}
	if srv.QueriesFor("gone.example.net", dnsmessage.TypeA) == 0 {
		t.Error("the in-scope CNAME target was never looked up")
	}
}
