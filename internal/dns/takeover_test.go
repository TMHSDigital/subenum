package dns

import (
	"context"
	"slices"
	"strings"
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
		"site.animaapp.io":               "anima",
		"forum.trydiscourse.com.":        "discourse",
		"herokuapp.com.evil.example.com": "",
		"animaapp.io.evil.example.com":   "",
		"trydiscourse.com.evil.test":     "",
		"cdn.example.net":                "",
	} {
		if got := TakeoverProvider(target); got != want {
			t.Errorf("TakeoverProvider(%q) = %q, want %q", target, got, want)
		}
	}
}

// TestParseTakeoverProviders covers #219: a file extends the built-in list,
// replaces or removes a listed suffix, can be used alone, and bad lines are
// reported with their line number.
func TestParseTakeoverProviders(t *testing.T) {
	lines := []string{
		"# in-house hosting",
		"",
		".pages.example-cdn.net  example-cdn",
		"special.cloudfront.net cf-special",
		".herokuapp.com my-heroku",
		".github.io -",
		"bücher.example buecher",
	}
	p, err := ParseTakeoverProviders(lines, false)
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{
		"site.pages.example-cdn.net": "example-cdn",
		"x.special.cloudfront.net":   "cf-special",     // longest suffix wins
		"x.cloudfront.net":           "aws-cloudfront", // built-in kept
		"acme.herokuapp.com":         "my-heroku",      // replaced
		"acme.github.io":             "",               // removed
		"x.xn--bcher-kva.example":    "buecher",        // IDN suffix in punycode
		"example-cdn.net":            "",
	} {
		if got := p.Match(target); got != want {
			t.Errorf("Match(%q) = %q, want %q", target, got, want)
		}
	}
	if TakeoverProvider("acme.github.io") != "github-pages" {
		t.Error("parsing a file changed the built-in list")
	}

	only, err := ParseTakeoverProviders([]string{".pages.example-cdn.net example-cdn"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if only.Match("x.cloudfront.net") != "" || only.Match("a.pages.example-cdn.net") != "example-cdn" {
		t.Errorf("only list = %v", only)
	}
	if empty, err := ParseTakeoverProviders(nil, true); err != nil || empty == nil || empty.Match("a.github.io") != "" {
		t.Errorf("an empty only list must match nothing, got %v (err %v)", empty, err)
	}

	for _, tc := range []struct{ line, want string }{
		{".example.net", "line 2: want"},
		{".example.net a b", "line 2: want"},
		{"https://example.net/x name", "line 2: "},
		{".example.net Bad_Name", "line 2: provider name"},
		{".example.net -name", "line 2: provider name"},
		{"com tld-only", "line 2: "},
	} {
		_, err := ParseTakeoverProviders([]string{"# ok", tc.line}, false)
		if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want prefix %q", tc.line, err, tc.want)
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
			recs, _, _ := Lookup{Resolver: r, Timeout: time.Second, Types: []string{"A", "CNAME"}}.ResolveTypes(context.Background(), name)
			if got := TakeoverHint(context.Background(), Lookup{Resolver: r, Timeout: time.Second, Attempts: 1}, recs); got != want {
				t.Errorf("TakeoverHint(%v) = %q, want %q", recs, got, want)
			}
		})
	}
}

// TestResolveNSMXTXT covers #194: -type NS, MX and TXT look the records up,
// a name without them is a negative, and a delegation whose name server does
// not exist gets the dangling-ns hint while a healthy one gets none.
func TestResolveNSMXTXT(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "example.com":
			return dnstest.Reply{MX: []string{"10 mx1.example.com"}, TXT: []string{"v=spf1 -all"}}
		case "ok.example.com":
			return dnstest.Reply{NS: []string{"ns1.example.net"}}
		case "gone.example.com":
			return dnstest.Reply{NS: []string{"ns1.example.net", "ns.unregistered.example"}}
		case "ns1.example.net":
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"192.0.2.53"}}
			}
			return dnstest.Reply{}
		case "www.example.com":
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"192.0.2.1"}}
			}
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	l := Lookup{Resolver: NewResolver(time.Second, srv.Addr), Timeout: time.Second, Attempts: 1, Types: []string{"NS", "MX", "TXT"}}
	ctx := context.Background()

	recs, outcome := l.Resolve(ctx, "example.com")
	want := []Record{{Type: "MX", Value: "10 mx1.example.com"}, {Type: "TXT", Value: "v=spf1 -all"}}
	if outcome != OutcomeFound || !slices.Equal(recs, want) {
		t.Errorf("example.com = %v %v, want %v", recs, outcome, want)
	}
	if _, outcome := l.Resolve(ctx, "www.example.com"); outcome != OutcomeNXDomain {
		t.Errorf("www.example.com (A only) = %v, want a negative", outcome)
	}
	for name, hint := range map[string]string{"ok.example.com": "", "gone.example.com": DanglingNS} {
		recs, outcome := l.Resolve(ctx, name)
		if outcome != OutcomeFound || len(recs) == 0 || recs[0].Type != "NS" {
			t.Fatalf("%s = %v %v, want NS records", name, recs, outcome)
		}
		if got := TakeoverHint(ctx, l, recs); got != hint {
			t.Errorf("TakeoverHint(%s) = %q, want %q", name, got, hint)
		}
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
				if got := c.Hint(context.Background(), Lookup{Resolver: r, Timeout: time.Second, Attempts: 1}, recs); got != want {
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
