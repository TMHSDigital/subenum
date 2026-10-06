package subenum

import (
	"reflect"
	"testing"

	"github.com/TMHSDigital/subenum/internal/scan"
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

// TestFieldNames covers rendering engine messages for a library caller:
// setting tokens become the Config fields a caller sets (#100). The messages
// are the real ones from internal/scan.
func TestFieldNames(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Results would be meaningless. Use {force} to scan anyway.", "Results would be meaningless. Use Force to scan anyway."},
		{"refusing to scan example.com: it is out of scope ({exclude})", "refusing to scan example.com: it is out of scope (Exclude)"},
		{
			"refusing to start: {recursive} {depth} 3 with 5000 entries can generate up to 1.3e+11 queries; set {max_queries} or {force}",
			"refusing to start: Recursive Depth 3 with 5000 entries can generate up to 1.3e+11 queries; set MaxQueries or Force",
		},
		{"concurrency ({concurrency}) must be at least 1, got 0", "concurrency (Concurrency) must be at least 1, got 0"},
		{"hit rate ({hit_rate}) must be 1-100, got 200", "hit rate (HitRate) must be 1-100, got 200"},
		// Text without tokens, flags in prose and unknown tokens stay put.
		{"a well-known host had a timeout", "a well-known host had a timeout"},
		{"pass -not-a-real-flag or {not_a_setting}", "pass -not-a-real-flag or {not_a_setting}"},
		{"", ""},
	}
	for _, c := range cases {
		if got := fieldNames(c.in); got != c.want {
			t.Errorf("fieldNames(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// TestConfigFieldsCoverEverySetting: every engine setting has a Config field
// a caller can actually set, so no token reaches a caller unrendered.
func TestConfigFieldsCoverEverySetting(t *testing.T) {
	cfg := reflect.TypeOf(Config{})
	for _, st := range scan.Settings {
		field, ok := configFields[st]
		if !ok {
			t.Errorf("setting %q has no Config field", st)
			continue
		}
		if _, ok := cfg.FieldByName(field); !ok {
			t.Errorf("setting %q maps to %q, which is not a Config field", st, field)
		}
	}
}
