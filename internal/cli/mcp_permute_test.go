package cli

import (
	"encoding/json"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"golang.org/x/net/dns/dnsmessage"
)

// mcpTestZone answers A for names, NS and the transfer for the apex, and
// NXDOMAIN for the rest, as a scan's preflight and wildcard probes expect.
func mcpTestZone(t *testing.T, apex string, names, transfer []string) *dnstest.Server {
	t.Helper()
	return dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Type == dnsmessage.TypeAXFR && transfer != nil:
			return dnstest.Reply{Transfer: transfer}
		case q.Name == apex && q.Type == dnsmessage.TypeNS:
			return dnstest.Reply{NS: []string{"ns1." + apex}}
		case q.Name == "ns1."+apex && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"127.0.0.1"}}
		case q.Name == apex || q.Name == "ns1."+apex:
			return dnstest.Reply{}
		case slices.Contains(names, q.Name):
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"192.0.2.10"}}
			}
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
}

// callReport makes one tool call and decodes its report.
func callReport(t *testing.T, call func() (string, bool)) mcpReport {
	t.Helper()
	text, _ := call()
	var r mcpReport
	if err := json.Unmarshal([]byte(text), &r); err != nil {
		t.Fatalf("not a scan report: %s", text)
	}
	return r
}

// TestMCPScanPermute covers #405: permute runs a second pass over variants
// of the names found, within what is left of max_queries, and its finds join
// the results.
func TestMCPScanPermute(t *testing.T) {
	t.Parallel()
	srv := mcpTestZone(t, "example.test", []string{"api.example.test", "api-dev.example.test"}, nil)
	tool := scanTool(mcpConfig{allow: []string{"example.test"}, dnsServer: srv.Addr, maxQueries: 1000, rate: 1000,
		maxDuration: time.Minute, timeout: 5 * time.Second, maxCalls: 10})
	call := func(args string) func() (string, bool) {
		return func() (string, bool) {
			r := tool.Call(t.Context(), json.RawMessage(args))
			return r.Text, r.IsError
		}
	}

	r := callReport(t, call(`{"domain": "example.test", "words": ["api", "www"], "types": ["A"], "permute": true}`))
	p := r.Permutation
	if p == nil {
		t.Fatalf("no permutation in the report: %+v", r)
	}
	var names []string
	for _, res := range r.Results {
		names = append(names, res.Name)
	}
	if !slices.Contains(names, "api-dev.example.test") || r.Found != 2 {
		t.Errorf("results %v, want api and the variant api-dev", names)
	}
	if p.Found != 1 || p.Tested == 0 || p.Tested != int64(p.Candidates) || p.Verdict != "complete" {
		t.Errorf("permutation %+v, want every variant tested, one found, complete", p)
	}

	// Without permute there is no pass and no variant.
	r = callReport(t, call(`{"domain": "example.test", "words": ["api", "www"], "types": ["A"]}`))
	if r.Permutation != nil || r.Found != 1 {
		t.Errorf("without permute: found %d, permutation %+v", r.Found, r.Permutation)
	}

	// A budget the scan spends leaves the pass nothing.
	r = callReport(t, call(`{"domain": "example.test", "words": ["api", "www"], "types": ["A"], "permute": true, "max_queries": 2}`))
	if p := r.Permutation; p == nil || p.Tested != 0 || p.Skipped == 0 || p.Verdict != "degraded" {
		t.Errorf("max_queries spent by the scan: %+v, want every variant skipped and degraded", p)
	}

	// Part of the budget left: the pass tests that many.
	r = callReport(t, call(`{"domain": "example.test", "words": ["api", "www"], "types": ["A"], "permute": true, "max_queries": 5}`))
	if p := r.Permutation; p == nil || p.Tested != 3 || p.Skipped != int64(p.Candidates)-3 {
		t.Errorf("max_queries 5: %+v, want 3 variants tested and the rest skipped", p)
	}
}

// TestE2EMCPLabScanPermute covers #405: lab_scan accepts permute, so agents
// can practise it; lab1 has no variants of its names, so the pass finds
// nothing but tests them.
func TestE2EMCPLabScanPermute(t *testing.T) {
	t.Parallel()
	_, replies := runMCPSession(t, []string{"-max-queries", "1000"},
		mcpCall{"lab_scan", `{"words": ["www", "mail"], "permute": true}`},
	)
	r := mcpReportOf(t, replies[0])
	if p := r.Permutation; p == nil || p.Candidates == 0 || p.Tested != int64(p.Candidates) || p.Found != 0 || p.Verdict != "complete" {
		t.Errorf("lab_scan permute: %+v", r.Permutation)
	}
}

// TestMCPScanZoneTransfer covers #405: zone_transfer is refused unless the
// server was started with -axfr, and with it the report says which name
// servers allowed a transfer and the names it gave are verified like words.
func TestMCPScanZoneTransfer(t *testing.T) {
	t.Parallel()
	srv := mcpTestZone(t, "example.test", []string{"zt.example.test", "gone.example.test"}, []string{"zt.example.test", "stale.example.test"})
	_, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	cfg := mcpConfig{allow: []string{"example.test"}, dnsServer: srv.Addr, maxQueries: 100, rate: 1000,
		maxDuration: time.Minute, timeout: 5 * time.Second, maxCalls: 10, transferPort: port}

	off := scanTool(cfg)
	r := off.Call(t.Context(), json.RawMessage(`{"domain": "example.test", "words": ["www"], "zone_transfer": true}`))
	if !r.IsError || !strings.Contains(r.Text, "the operator did not start the server with -axfr") {
		t.Errorf("zone_transfer without -axfr: %+v", r)
	}
	if n := srv.QueriesFor("example.test", dnsmessage.TypeAXFR); n != 0 {
		t.Errorf("a refused call asked for %d transfers", n)
	}

	cfg.axfr = true
	on := scanTool(cfg)
	report := callReport(t, func() (string, bool) {
		r := on.Call(t.Context(), json.RawMessage(`{"domain": "example.test", "words": ["www"], "types": ["A"], "zone_transfer": true}`))
		return r.Text, r.IsError
	})
	z := report.ZoneTransfer
	if z == nil || z.Names != 2 || !slices.Equal(z.Allowed, []string{"ns1.example.test"}) || z.Error != "" {
		t.Fatalf("zone_transfer: %+v", z)
	}
	if report.Found != 1 || report.Results[0].Name != "zt.example.test" {
		t.Errorf("results %+v, want the transferred name that resolves", report.Results)
	}

	// An excluded name server is never asked.
	before := srv.QueriesFor("example.test", dnsmessage.TypeAXFR)
	report = callReport(t, func() (string, bool) {
		r := on.Call(t.Context(), json.RawMessage(`{"domain": "example.test", "words": ["www"], "types": ["A"], "zone_transfer": true, "exclude": ["ns1.example.test"]}`))
		return r.Text, r.IsError
	})
	if n := srv.QueriesFor("example.test", dnsmessage.TypeAXFR); n != before {
		t.Errorf("an excluded name server was asked for a transfer")
	}
	if report.ZoneTransfer == nil || len(report.ZoneTransfer.Allowed) != 0 {
		t.Errorf("excluded name server: %+v", report.ZoneTransfer)
	}
}

// TestMCPAXFRFlag covers #405: -axfr adds zone_transfer to scan's schema.
func TestMCPAXFRFlag(t *testing.T) {
	cfg, code, ok := parseMCPFlags([]string{"-allow", "example.com", "-axfr"}, &strings.Builder{})
	if !ok || code != exitOK || !cfg.axfr {
		t.Fatalf("-axfr: ok %v code %d axfr %v", ok, code, cfg.axfr)
	}
	if !strings.Contains(string(scanTool(cfg).InputSchema), `"zone_transfer"`) {
		t.Error("scan's schema has no zone_transfer with -axfr")
	}
}
