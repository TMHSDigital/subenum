package dns

import (
	"context"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

func TestTakeoverProvider(t *testing.T) {
	for target, want := range map[string]string{
		"acme.herokuapp.com.":            "heroku",
		"ACME.GitHub.io":                 "github-pages",
		"bucket.s3.amazonaws.com":        "aws-s3",
		"site.azurewebsites.net":         "azure",
		"herokuapp.com.evil.example.com": "",
		"cdn.example.net":                "",
	} {
		if got := TakeoverProvider(target); got != want {
			t.Errorf("TakeoverProvider(%q) = %q, want %q", target, got, want)
		}
	}
}

// TestTakeoverHint is #71's done-when: in a test zone, a dangling CNAME and a
// provider CNAME are marked, found through the same CNAME lookup a scan does.
func TestTakeoverHint(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"dangling.example.com": {CNAME: "gone.example.net"},       // target does not exist
		"app.example.com":      {CNAME: "acme.herokuapp.com"},     // provider, alive
		"acme.herokuapp.com":   {A: "192.0.2.20"},                 //
		"old.example.com":      {CNAME: "old-acme.herokuapp.com"}, // provider, dangling
		"www.example.com":      {A: "192.0.2.1"},                  // no CNAME
		"cdn.example.com":      {CNAME: "edge.example.net"},       // healthy, not a provider
		"edge.example.net":     {A: "192.0.2.30"},
	})
	r := srv.Resolver(time.Second)
	for name, want := range map[string]string{
		"dangling.example.com": "dangling",
		"app.example.com":      "provider:heroku",
		"old.example.com":      "dangling:heroku",
		"www.example.com":      "",
		"cdn.example.com":      "",
	} {
		t.Run(name, func(t *testing.T) {
			recs, _, _ := ResolveTypes(context.Background(), r, name, time.Second, []string{"A", "CNAME"})
			if got := TakeoverHint(context.Background(), r, recs, time.Second, 1); got != want {
				t.Errorf("TakeoverHint(%v) = %q, want %q", recs, got, want)
			}
		})
	}
}

// TestTakeoverCache covers #121: many names aliased to one CNAME target cost
// one lookup of it, even when they arrive at once, and the hints match
// TakeoverHint's.
func TestTakeoverCache(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.Name == "acme.herokuapp.com" {
			return dnstest.Reply{A: []string{"192.0.2.20"}}
		}
		return dnstest.NXDomain
	})
	r := NewResolver(time.Second, srv.Addr)
	var c TakeoverCache
	targets := map[string]string{"gone.example.net": "dangling", "acme.herokuapp.com": "provider:heroku"}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		for target, want := range targets {
			wg.Go(func() {
				recs := []Record{{Type: "CNAME", Value: target}}
				if got := c.Hint(context.Background(), r, recs, time.Second, 1); got != want {
					t.Errorf("Hint(%s) = %q, want %q", target, got, want)
				}
			})
		}
	}
	wg.Wait()
	if c.Lookups() != 2 {
		t.Errorf("cache sent %d target lookups, want 2", c.Lookups())
	}
	for target := range targets {
		if n := srv.QueriesFor(target, dnsmessage.TypeA); n != 1 {
			t.Errorf("server saw %d A queries for %s, want 1", n, target)
		}
	}
}
