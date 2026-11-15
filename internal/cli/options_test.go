package cli

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// TestScanOptionsSetsEveryField is the CLI's drift guard of #262: with every
// input set, scanOptions fills in every scan.Options field. A field added to
// scan.Options fails here until the CLI maps it or lists it in cliUnmapped
// with a reason.
func TestScanOptionsSetsEveryField(t *testing.T) {
	cliUnmapped := map[string]string{}

	f := cliFlags{
		concurrency: 7, timeoutMs: 700, dnsServer: "192.0.2.53:53", testMode: true, testHitRate: 40,
		seed: 9, force: true, recursive: true, depth: 3, rate: 50, autoRate: true,
		maxDuration: time.Minute, retryIncon: true, ratePerRes: 5, noAbort: true, verbose: true,
	}
	in := &runtimeInputs{
		maxAttempts: 2, recordTypes: []string{"A"}, excludes: []string{"vpn.example.com"},
		pool:      dns.NewPool([]string{"192.0.2.1:53"}, time.Second),
		providers: dns.TakeoverProviders{}, deadline: time.Now().Add(time.Minute),
	}
	p := scanPass{domain: "example.com", entries: []string{"www"}, maxQueries: 10, resumeFrom: 1, resumeNames: []string{"www.example.com"}}
	opts := scanOptions(f, in, p, func(string, ...any) {})
	checkEveryOptionSet(t, opts, cliUnmapped)
}

// TestRangeErrorsNameFlags pins the CLI messages for the two checks that
// moved into scan.Options.Validate (#262): they name the flag and are usage
// errors, as before.
func TestRangeErrorsNameFlags(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-simulate", "-rate-per-resolver", "-1", "example.com"},
			"rate per resolver (-rate-per-resolver) must be 0 (unlimited) or a positive integer, got -1"},
		{[]string{"-simulate", "-max-duration", "-1s", "example.com"},
			"max duration (-max-duration) must be 0 (unlimited) or positive, got -1s"},
	} {
		var stderr bytes.Buffer
		code := runWith(runArgs{args: c.args, stdin: strings.NewReader(""), stdout: io.Discard, stderr: &stderr})
		if code != exitUsage || !strings.Contains(stderr.String(), c.want) {
			t.Errorf("%v: exit %d, stderr %q; want exit %d and %q", c.args, code, stderr.String(), exitUsage, c.want)
		}
	}
}

// checkEveryOptionSet fails for each scan.Options field that is zero and not
// listed in unmapped, and for each unmapped entry that names no field or a
// field that is set after all.
func checkEveryOptionSet(t *testing.T, opts scan.Options, unmapped map[string]string) {
	t.Helper()
	v := reflect.ValueOf(opts)
	for i := range v.NumField() {
		name := v.Type().Field(i).Name
		_, listed := unmapped[name]
		switch zero := v.Field(i).IsZero(); {
		case zero && !listed:
			t.Errorf("scan.Options.%s is never set; map it or list it as unmapped with a reason", name)
		case !zero && listed:
			t.Errorf("scan.Options.%s is set but listed as unmapped", name)
		}
	}
	for name := range unmapped {
		if _, ok := v.Type().FieldByName(name); !ok {
			t.Errorf("unmapped lists %s, which scan.Options does not have", name)
		}
	}
}
