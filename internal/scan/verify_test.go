package scan

import (
	"context"
	"testing"

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
