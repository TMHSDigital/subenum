package scan

import (
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

func TestStatsVerdict(t *testing.T) {
	for _, tc := range []struct {
		name        string
		s           Stats
		interrupted bool
		want        string
		reason      string
	}{
		{"clean", Stats{Found: 5, NXDomain: 995}, false, VerdictComplete, "all 1000"},
		{"few failures", Stats{NXDomain: 999, Timeout: 1}, false, VerdictComplete, "under 1%"},
		{"some failures", Stats{NXDomain: 860, Timeout: 140}, false, VerdictDegraded, "140 of 1000"},
		{"many failures", Stats{NXDomain: 700, Timeout: 300}, false, VerdictUnreliable, "300 of 1000"},
		{"guard abort", Stats{NXDomain: 10, Timeout: 190, Aborted: true}, false, VerdictUnreliable, "reliability guard"},
		{"capped", Stats{NXDomain: 10, Skipped: 90}, false, VerdictDegraded, "90 candidates"},
		{"interrupted", Stats{NXDomain: 10}, true, VerdictDegraded, "interrupted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, reason := tc.s.Verdict(tc.interrupted)
			if v != tc.want || !strings.Contains(reason, tc.reason) {
				t.Errorf("Verdict() = %q, %q; want %q mentioning %q", v, reason, tc.want, tc.reason)
			}
		})
	}
}

// TestRunStatsReportRunFacts covers #70: EventDone carries the facts the
// quality report needs.
func TestRunStatsReportRunFacts(t *testing.T) {
	cfg := Config{
		Domain: "example.com", Entries: makeEntries(50), Concurrency: 4,
		Simulate: true, HitRate: 0, Attempts: 1, MaxQueries: 10,
	}
	events := make(chan Event, 64)
	go Run(t.Context(), cfg, events)
	done, _, _ := collect(events)
	if done == nil {
		t.Fatal("no EventDone")
	}
	if done.Stats.Skipped != 40 {
		t.Errorf("Skipped = %d, want 40", done.Stats.Skipped)
	}
	if v, _ := done.Stats.Verdict(false); v != VerdictDegraded {
		t.Errorf("capped scan verdict = %q, want degraded", v)
	}
}

// TestRunCountsWireQueries: a live scan reports the queries it sent.
func TestRunCountsWireQueries(t *testing.T) {
	addr, stop := startUDPDNS(t, func(string, uint16) ([4]byte, bool) { return [4]byte{}, false })
	defer stop()
	cfg := Config{
		Domain: "example.com", Entries: []string{"www", "mail"}, Concurrency: 2,
		Timeout: time.Second, Attempts: 1, Types: []string{"A"},
		Resolver: dns.NewResolver(time.Second, addr), DNSServer: addr,
	}
	events := make(chan Event, 64)
	go Run(t.Context(), cfg, events)
	done, _, _ := collect(events)
	// Preflight, five root wildcard probes, two names: one A query each.
	if done == nil || done.Stats.QueriesSent < 8 {
		t.Fatalf("QueriesSent = %+v, want at least 8", done)
	}
}
