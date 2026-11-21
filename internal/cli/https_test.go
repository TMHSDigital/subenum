package cli

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// TestE2EHTTPS covers #438's acceptance criteria end to end against a local
// DNS server: -type A,HTTPS reports HTTPS records in text (-show-records),
// JSON, JSONL and CSV output; a name whose only record is an HTTPS alias is
// found; an AliasMode target on a takeover-prone provider is flagged like a
// CNAME target; -follow-records tests an in-scope alias target; and
// -dry-run counts the extra query.
func TestE2EHTTPS(t *testing.T) {
	t.Parallel()
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "example.com":
			return dnstest.Reply{}
		case "www.example.com":
			return dnstest.Reply{A: []string{"192.0.2.10"}, HTTPS: []string{"1 . alpn=h2,h3 port=443"}}
		case "pages.example.com":
			return dnstest.Reply{HTTPS: []string{"0 acme.github.io"}}
		case "acme.github.io":
			return dnstest.Reply{A: []string{"192.0.2.30"}}
		case "cdn.example.com":
			return dnstest.Reply{HTTPS: []string{"0 edge.example.com"}}
		case "edge.example.com":
			return dnstest.Reply{A: []string{"192.0.2.20"}}
		}
		return dnstest.NXDomain
	})
	wl := writeFile(t, "wl.txt", "www\npages\ncdn\nnope\n")
	scanWith := func(extra ...string) string {
		t.Helper()
		args := append(localArgs(append([]string{"-dns-server", srv.Addr, "-type", "A,HTTPS", "-progress=false", "-w", wl}, extra...)...), "example.com")
		code, out := runCLIWith(t, runArgs{args: args})
		if code != exitOK {
			t.Fatalf("%v: exit %d\n%s", extra, code, out)
		}
		return out
	}

	got := seenResults(t, scanWith("-format", "jsonl", "-follow-records"))
	wwwHTTPS := dns.Record{Type: "HTTPS", Value: "1 . alpn=h2,h3 port=443"}
	if r := got["www.example.com"]; !slices.Contains(r.Records, wwwHTTPS) || !slices.Contains(r.Records, dns.Record{Type: "A", Value: "192.0.2.10"}) {
		t.Errorf("www: records %v, want its A and HTTPS records", r.Records)
	}
	if r := got["pages.example.com"]; !slices.Equal(r.Records, []dns.Record{{Type: "HTTPS", Value: "0 acme.github.io"}}) || r.Takeover != "provider:github-pages" {
		t.Errorf("pages: records %v takeover %q, want its alias flagged provider:github-pages", r.Records, r.Takeover)
	}
	if r, ok := got["edge.example.com"]; !ok || !slices.Equal(r.Sources, []string{"records"}) {
		t.Errorf("edge: %+v (found %v), want a -follow-records hit", r, ok)
	}
	if _, ok := got["nope.example.com"]; ok {
		t.Error("nope.example.com reported")
	}

	type jsonResult struct {
		Subdomain string       `json:"subdomain"`
		Records   []dns.Record `json:"records"`
	}
	var results []jsonResult
	if err := json.Unmarshal([]byte(scanWith("-format", "json")), &results); err != nil {
		t.Fatalf("json: %v", err)
	}
	if i := slices.IndexFunc(results, func(r jsonResult) bool { return r.Subdomain == "www.example.com" }); i < 0 || !slices.Contains(results[i].Records, wwwHTTPS) {
		t.Errorf("json: %+v, want www's HTTPS record", results)
	}

	if out := scanWith("-format", "csv"); !strings.Contains(out, "HTTPS") || !strings.Contains(out, "1 . alpn=h2,h3 port=443") {
		t.Errorf("csv lacks the HTTPS record:\n%s", out)
	}
	if out := scanWith("-show-records"); !strings.Contains(out, "www.example.com A=192.0.2.10 HTTPS=1 . alpn=h2,h3 port=443") ||
		!strings.Contains(out, "pages.example.com HTTPS=0 acme.github.io TAKEOVER?=provider:github-pages") {
		t.Errorf("text with -show-records:\n%s", out)
	}

	for types, want := range map[string]int64{"A": 4, "A,HTTPS": 8} {
		_, plans := dryRunPlans(t, "-simulate", "-type", types, "-w", wl, "example.com")
		if len(plans) != 1 || plans[0].Queries != want {
			t.Errorf("dry run -type %s: %+v, want %d queries", types, plans, want)
		}
	}
}

// TestRecordTargetsHTTPS covers #438 for a resumed -follow-records scan: an
// HTTPS target is queued again like a CNAME target, a "." target is not.
func TestRecordTargetsHTTPS(t *testing.T) {
	got := recordTargets([]output.Result{
		{Result: scan.Result{Subdomain: "cdn.example.com", Records: []dns.Record{{Type: "HTTPS", Value: "0 Edge.example.com"}}}},
		{Result: scan.Result{Subdomain: "www.example.com", Records: []dns.Record{{Type: "HTTPS", Value: "1 . alpn=h2"}, {Type: "HTTPS", Value: "2 alt.example.com port=8443"}}}},
	})
	if want := []string{"edge.example.com", "alt.example.com"}; !slices.Equal(got, want) {
		t.Errorf("recordTargets = %v, want %v", got, want)
	}
}
