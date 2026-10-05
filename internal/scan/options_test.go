package scan

import (
	"strings"
	"testing"
	"time"
)

func validOptions() Options {
	return Options{
		Domain: "example.com", Concurrency: 10, TimeoutMs: 500, DNSServer: "1.1.1.1:53",
		HitRate: 15, Attempts: 1, Depth: 1,
	}
}

// TestOptionsValidate covers the shared validator both front ends call (#80).
func TestOptionsValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mut     func(*Options)
		wantErr string
	}{
		{"valid", func(*Options) {}, ""},
		{"concurrency", func(o *Options) { o.Concurrency = 0 }, "concurrency"},
		{"timeout", func(o *Options) { o.TimeoutMs = 0 }, "timeout"},
		{"attempts", func(o *Options) { o.Attempts = 0 }, "attempts"},
		{"depth", func(o *Options) { o.Depth = 0 }, "depth"},
		{"rate", func(o *Options) { o.Rate = -1 }, "rate"},
		{"max queries", func(o *Options) { o.MaxQueries = -1 }, "max queries"},
		{"bad resolver live", func(o *Options) { o.DNSServer = "nope" }, "DNS server"},
		{"bad resolver ignored when simulating", func(o *Options) { o.DNSServer = "nope"; o.Simulate = true }, ""},
		{"hit rate checked when simulating", func(o *Options) { o.Simulate = true; o.HitRate = 0 }, "hit rate"},
		{"hit rate ignored live", func(o *Options) { o.HitRate = 0 }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := validOptions()
			tc.mut(&o)
			err := o.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestOptionsConfig(t *testing.T) {
	o := validOptions()
	o.TimeoutMs = 750
	if cfg := o.Config(); cfg.Timeout != 750*time.Millisecond || cfg.Domain != o.Domain || cfg.Concurrency != 10 {
		t.Fatalf("Config() = %+v", cfg)
	}
}
