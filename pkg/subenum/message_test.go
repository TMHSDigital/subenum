package subenum

import (
	"reflect"
	"testing"

	"github.com/TMHSDigital/subenum/internal/validate"
)

// TestDefaultsMatchTheCLI keeps the documented defaults in step with the ones
// the command line uses. DefaultResolver is spelled out rather than aliased so
// that it reads as a plain string in the generated documentation.
func TestDefaultsMatchTheCLI(t *testing.T) {
	if DefaultResolver != validate.DefaultDNSServer {
		t.Errorf("DefaultResolver = %q, but the CLI defaults to %q", DefaultResolver, validate.DefaultDNSServer)
	}
}

// TestFieldNames covers the rewriting of engine messages, which name
// command-line flags, into the Config fields a library caller sets. The
// messages are the real ones from internal/scan and internal/dns.
func TestFieldNames(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			"Results would be meaningless. Use -force to scan anyway.",
			"Results would be meaningless. Use Force to scan anyway.",
		},
		{
			"refusing to scan example.com: it is out of scope (-exclude)",
			"refusing to scan example.com: it is out of scope (Exclude)",
		},
		{
			"refusing to start: -recursive -depth 3 with 5000 entries can generate up to 1.3e+11 queries; set -max-queries or -force",
			"refusing to start: Recursive Depth 3 with 5000 entries can generate up to 1.3e+11 queries; set MaxQueries or Force",
		},
		{
			"-max-queries reached; 12 candidates not tested",
			"MaxQueries reached; 12 candidates not tested",
		},
		{
			"query cap reached (-max-queries 100); skipped 9 additional jobs",
			"query cap reached (MaxQueries 100); skipped 9 additional jobs",
		},
		{
			"concurrency (-t) must be at least 1, got 0",
			"concurrency (Concurrency) must be at least 1, got 0",
		},
		{
			"timeout (-timeout) must be at least 1 ms, got 0",
			"timeout (Timeout) must be at least 1 ms, got 0",
		},
		{
			"hit rate (-hit-rate) must be 1-100, got 200",
			"hit rate (HitRate) must be 1-100, got 200",
		},
		// A flag whose name is a prefix of a longer one must not be
		// mistaken for it, in either direction.
		{"set -t 50 and -type A", "set Concurrency 50 and Types A"},
		{"set -r hosts and -rate 20", "set ResolverPool hosts and Rate 20"},
		// Hyphens in prose, and a rate that is not the flag, stay put.
		{
			"80% of 200 queries failed (timeout/refused/other); likely resolver rate-limiting at -t 100 and -rate 0",
			"80% of 200 queries failed (timeout/refused/other); likely resolver rate-limiting at Concurrency 100 and Rate 0",
		},
		{"a well-known host had a timeout", "a well-known host had a timeout"},
		{"wildcard detection failed: i/o timeout", "wildcard detection failed: i/o timeout"},
		// A flag with no matching field is left alone rather than mangled.
		{"pass -not-a-real-flag to continue", "pass -not-a-real-flag to continue"},
		{"", ""},
	}
	for _, c := range cases {
		if got := fieldNames(c.in); got != c.want {
			t.Errorf("fieldNames(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// TestFlagFieldsNameRealFields guards against a typo in the table: every
// value must be a field a caller can actually set on Config.
func TestFlagFieldsNameRealFields(t *testing.T) {
	cfg := reflect.TypeOf(Config{})
	for flag, field := range flagFields {
		if _, ok := cfg.FieldByName(field); !ok {
			t.Errorf("-%s maps to %q, which is not a Config field", flag, field)
		}
	}
}
