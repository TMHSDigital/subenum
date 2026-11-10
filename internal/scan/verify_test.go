package scan

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

func TestVerify(t *testing.T) {
	want := map[string]dns.Outcome{
		"a.example.com": dns.OutcomeFound,
		"b.example.com": dns.OutcomeNXDomain,
		"c.example.com": dns.OutcomeTimeout,
	}
	cfg := Config{
		Concurrency: 2,
		Exclude:     []string{"skip.example.com"},
		resolveHook: func(_ context.Context, name string) ([]dns.Record, dns.Outcome) {
			if name == "skip.example.com" {
				t.Error("an excluded name was looked up")
			}
			return nil, want[name]
		},
	}
	got, _ := Verify(context.Background(), cfg, []string{"a.example.com", "b.example.com", "c.example.com", "skip.example.com"})
	if len(got) != len(want) {
		t.Fatalf("got %d outcomes, want %d: %v", len(got), len(want), got)
	}
	for name, o := range want {
		if got[name] != o {
			t.Errorf("%s: %v, want %v", name, got[name], o)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, _ = Verify(ctx, cfg, []string{"a.example.com", "b.example.com"})
	for name, o := range got {
		if o != dns.OutcomeCanceled && o != dns.OutcomeFound {
			t.Errorf("cancelled: %s = %v", name, o)
		}
	}
}

// TestVerifyCancelledMidwayReportsEveryName covers #151: names never handed
// to a worker are reported cancelled, not left out (which reads as found).
func TestVerifyCancelledMidwayReportsEveryName(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := Config{
		Concurrency: 1,
		Exclude:     []string{"skip.example.com"},
		resolveHook: func(context.Context, string) ([]dns.Record, dns.Outcome) {
			cancel()
			return nil, dns.OutcomeNXDomain
		},
	}
	names := []string{"skip.example.com"}
	for i := range 50 {
		names = append(names, fmt.Sprintf("n%d.example.com", i))
	}
	got, _ := Verify(ctx, cfg, names)
	if len(got) != len(names)-1 {
		t.Fatalf("got %d outcomes, want %d (every name but the excluded one)", len(got), len(names)-1)
	}
	if _, ok := got["skip.example.com"]; ok {
		t.Error("the excluded name has an outcome")
	}
	for name, o := range got {
		if o == dns.OutcomeFound {
			t.Errorf("%s reported found after cancellation", name)
		}
	}
}

// scanFound runs a scan and returns the names it reported found.
func scanFound(t *testing.T, cfg Config) map[string]bool {
	t.Helper()
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	found := map[string]bool{}
	var done *Event
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			found[ev.Result.Subdomain] = true
		case EventError:
			t.Errorf("scan error: %s", ev.Message)
		case EventDone:
			done = &ev
		}
	}
	if done == nil {
		t.Fatal("no EventDone")
	}
	if done.Stats.Other != 0 || done.Stats.Timeout != 0 || done.Stats.Refused != 0 {
		t.Errorf("scan lookups failed: %+v", done.Stats)
	}
	return found
}

// TestVerifyResolvesLikeTheScan covers #163: the scan workers and Verify
// resolve through one entry point, so for every lookup mode Verify confirms
// exactly the names the scan found. Attempts: 0 means one attempt, not none.
func TestVerifyResolvesLikeTheScan(t *testing.T) {
	addr, _ := startUDPDNS(t, func(name string, _ uint16) ([4]byte, bool) {
		return [4]byte{192, 0, 2, 1}, name == "www.example.com" || name == "api.example.com"
	})
	cases := map[string]Config{
		"simulated": {Simulate: true, HitRate: 40, Seed: 7, Entries: makeEntries(100)},
		"hooked": {Simulate: true, Entries: makeEntries(100), resolveHook: func(_ context.Context, name string) ([]dns.Record, dns.Outcome) {
			if len(name)%2 == 0 {
				return []dns.Record{{Type: "A", Value: "192.0.2.1"}}, dns.OutcomeFound
			}
			return nil, dns.OutcomeNXDomain
		}},
		"live": {Entries: []string{"www", "mail", "api", "dev"}, Types: []string{"A"}, Resolver: dns.NewResolver(time.Second, addr), DNSServer: addr},
	}
	for name, cfg := range cases {
		for _, attempts := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("%s/attempts=%d", name, attempts), func(t *testing.T) {
				cfg.Domain, cfg.Concurrency, cfg.Timeout, cfg.Attempts = "example.com", 4, time.Second, attempts
				found := scanFound(t, cfg)
				if len(found) == 0 || len(found) == len(cfg.Entries) {
					t.Fatalf("scan found %d of %d names; want some but not all", len(found), len(cfg.Entries))
				}
				names := make([]string, len(cfg.Entries))
				for i, e := range cfg.Entries {
					names[i] = e + "." + cfg.Domain
				}
				got, _ := Verify(context.Background(), cfg, names)
				for _, n := range names {
					want := dns.OutcomeNXDomain
					if found[n] {
						want = dns.OutcomeFound
					}
					if got[n] != want {
						t.Errorf("%s: Verify says %v, scan says %v", n, got[n], want)
					}
				}
			})
		}
	}
}
