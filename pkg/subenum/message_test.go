package subenum

import (
	"reflect"
	"testing"
	"time"

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
	// The numeric defaults are literals for the same reason; the CLI flags
	// and the TUI form take theirs from scan (#262).
	if DefaultConcurrency != scan.DefaultConcurrency {
		t.Errorf("DefaultConcurrency = %d, scan.DefaultConcurrency = %d", DefaultConcurrency, scan.DefaultConcurrency)
	}
	if DefaultTimeout != scan.DefaultTimeoutMs*time.Millisecond {
		t.Errorf("DefaultTimeout = %s, scan.DefaultTimeoutMs = %d", DefaultTimeout, scan.DefaultTimeoutMs)
	}
	if DefaultHitRate != scan.DefaultHitRate {
		t.Errorf("DefaultHitRate = %d, scan.DefaultHitRate = %d", DefaultHitRate, scan.DefaultHitRate)
	}
}

// TestOptionsSetsEveryField is pkg/subenum's drift guard of #262: with every
// Config field set, options fills in every scan.Options field except the ones
// listed in pkgUnmapped, each with the reason.
func TestOptionsSetsEveryField(t *testing.T) {
	pkgUnmapped := map[string]string{
		"Simulate":      "mapped, but zero here: ResolverPool needs a live scan",
		"ResumeFrom":    "the library does not resume interrupted scans",
		"ResumeParents": "the library does not resume interrupted scans",
		"RetryPrior":    "the library does not resume interrupted scans",
		"ResumeFollow":  "the library does not resume interrupted scans",
		"Resolver":      "scan.Run builds the resolver from DNSServer",
		"ZoneServer":    "the library does not run labs; delegation queries go to the zone's name servers",
	}
	c := Config{
		Domain: "example.com", Words: []string{"www"}, Concurrency: 7, Timeout: 700 * time.Millisecond,
		Resolver: "192.0.2.53:53", HitRate: 40, Seed: 9, Attempts: 2, Force: true, Types: []string{"A"},
		Recursive: true, Depth: 3, RecursiveWords: []string{"x"}, FollowRecords: true, Rate: 50, AutoRate: true, MaxQueries: 10, MaxDuration: time.Minute,
		Exclude: []string{"vpn.example.com"}, NoAbort: true, Verbose: true, Logf: func(string, ...any) {},
		RetryInconclusive: true, RatePerResolver: 5, ResolverPool: []string{"192.0.2.1"},
		TakeoverProviders: []TakeoverProvider{{Suffix: ".example-cdn.net", Name: "example-cdn"}},
	}
	opts, err := c.options()
	if err != nil {
		t.Fatal(err)
	}
	for name, field := range opts.Fields() {
		_, listed := pkgUnmapped[name]
		switch zero := field.IsZero(); {
		case zero && !listed:
			t.Errorf("scan.Options.%s is never set from Config; map it or list it in pkgUnmapped with a reason", name)
		case !zero && listed:
			t.Errorf("scan.Options.%s is set from Config but listed in pkgUnmapped", name)
		}
	}
}

// TestRangeErrorsNameConfigFields pins the messages for the two checks that
// moved into scan.Options.Validate (#262): they still name the Config field.
func TestRangeErrorsNameConfigFields(t *testing.T) {
	for _, c := range []struct {
		cfg  Config
		want string
	}{
		{Config{Domain: "example.com", Words: []string{"www"}, RatePerResolver: -1},
			"subenum: rate per resolver (RatePerResolver) must be 0 (unlimited) or a positive integer, got -1"},
		{Config{Domain: "example.com", Words: []string{"www"}, MaxDuration: -time.Second},
			"subenum: max duration (MaxDuration) must be 0 (unlimited) or positive, got -1s"},
	} {
		if _, err := c.cfg.options(); err == nil || err.Error() != c.want {
			t.Errorf("error = %v, want %q", err, c.want)
		}
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
		field := scan.FieldName(st)
		if _, ok := cfg.FieldByName(field); !ok {
			t.Errorf("setting %q maps to %q, which is not a Config field", st, field)
		}
	}
}
