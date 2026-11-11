package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// TestE2EInternalAddress covers #218: a name that resolves to an internal
// address is reported with its scope, a name that resolves to a public one
// is not, and the run summary counts the internal ones.
func TestE2EInternalAddress(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "example.com":
			// The root answers with an address of its own, so the wildcard
			// fingerprint does not match the names below.
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"192.0.2.1"}}
			}
			return dnstest.Reply{}
		case "leaky.example.com":
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"10.0.0.1"}}
			}
			return dnstest.Reply{}
		case "public.example.com":
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"93.184.216.34"}}
			}
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	wl := writeFile(t, "wl.txt", "leaky\npublic\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	code, out := runCLI(t, "", "-dns-server", srv.Addr, "-type", "A", "-progress=false",
		"-format", "jsonl", "-stats", stats, "-w", wl, "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}

	scopes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var r struct {
			Type            string `json:"type"`
			Subdomain       string `json:"subdomain"`
			InternalAddress string `json:"internal_address"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		if r.Type != "summary" {
			scopes[r.Subdomain] = r.InternalAddress
		}
	}
	if got := scopes["leaky.example.com"]; got != "private" {
		t.Errorf("leaky.example.com scope = %q, want private (results: %v)", got, scopes)
	}
	if got := scopes["public.example.com"]; got != "" {
		t.Errorf("public.example.com scope = %q, want none (results: %v)", got, scopes)
	}

	data, err := os.ReadFile(stats)
	if err != nil {
		t.Fatalf("read stats: %v", err)
	}
	var sum struct {
		Targets []struct {
			Internal int64 `json:"internal_addresses"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &sum); err != nil {
		t.Fatalf("parse stats: %v", err)
	}
	if len(sum.Targets) != 1 || sum.Targets[0].Internal != 1 {
		t.Errorf("summary internal_addresses = %+v, want 1", sum.Targets)
	}
}
