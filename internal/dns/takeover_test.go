package dns

import (
	"context"
	"testing"
	"time"
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
