package scan

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

func TestScopeMatching(t *testing.T) {
	sc := newScope([]string{"VPN.example.com.", "*.dev.example.com"})
	for name, want := range map[string]bool{
		"vpn.example.com":      true,
		"VPN.Example.com":      true,
		"dev.example.com":      false, // *.dev covers names below dev, not dev itself
		"api.dev.example.com":  true,
		"a.b.dev.example.com":  true,
		"www.example.com":      false,
		"api.devx.example.com": false,
		"x.vpn.example.com":    false,
	} {
		if got := sc.excluded(name); got != want {
			t.Errorf("excluded(%q) = %v, want %v", name, got, want)
		}
	}
	if (*scope)(nil).excluded("x.example.com") {
		t.Error("nil scope excluded a name")
	}
	if err := ValidateExcludes([]string{"*.ok.example.com", "bad pattern"}); err == nil || !strings.Contains(err.Error(), "bad pattern") {
		t.Errorf("ValidateExcludes accepted an invalid pattern: %v", err)
	}
}

// TestRunExcludeSendsNoQueriesInBranch is #87's done-when: a recursive scan
// with -exclude '*.dev.example.com' never queries under that branch, wildcard
// probes included, and accounts for the excluded candidates.
func TestRunExcludeSendsNoQueriesInBranch(t *testing.T) {
	var mu sync.Mutex
	var queried []string
	addr, stop := startUDPDNSAction(t, func(name string) dnsAction {
		mu.Lock()
		queried = append(queried, name)
		mu.Unlock()
		if name == "dev.example.com" || name == "www.example.com" || strings.HasSuffix(name, ".dev.example.com") {
			return dnsAction{ip: [4]byte{192, 0, 2, 1}, hit: true}
		}
		return dnsAction{}
	})
	defer stop()

	cfg := Config{
		Domain: "example.com", Entries: []string{"dev", "www", "api"}, Concurrency: 2,
		Timeout: time.Second, Attempts: 1, Types: []string{"A"}, Recursive: true, Depth: 3,
		Exclude:  []string{"*.dev.example.com"},
		Resolver: dns.NewResolver(time.Second, addr), DNSServer: addr,
	}
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	done, errs, _ := collect(events)
	if len(errs) != 0 || done == nil {
		t.Fatalf("errs=%v done=%v", errs, done)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, q := range queried {
		if strings.HasSuffix(q, ".dev.example.com") {
			t.Fatalf("queried %s inside the excluded branch; all queries: %v", q, queried)
		}
	}
	// dev's three children are excluded at depth 2. www's children are in
	// scope: www.www, dev.www, api.www.
	if done.Stats.Excluded != 3 {
		t.Errorf("Excluded = %d, want 3", done.Stats.Excluded)
	}
}

func TestRunRefusesOutOfScopeTarget(t *testing.T) {
	cfg := Config{Domain: "a.corp.example.com", Entries: []string{"www"}, Concurrency: 1,
		Simulate: true, HitRate: 1, Attempts: 1, Exclude: []string{"*.corp.example.com"}}
	events := make(chan Event, 8)
	go Run(context.Background(), cfg, events)
	_, errs, _ := collect(events)
	if len(errs) != 1 || !strings.Contains(errs[0].Message, "out of scope") {
		t.Fatalf("errs = %v, want an out-of-scope refusal", errs)
	}
}
