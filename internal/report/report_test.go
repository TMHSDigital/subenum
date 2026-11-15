package report

import (
	"reflect"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// TestStatusRenderings pins how each target status is shown in the terminal
// and written to the report (#331).
func TestStatusRenderings(t *testing.T) {
	for _, tc := range []struct {
		s            Status
		label, value string
	}{
		{StatusNotRun, "not run", "not_run"},
		{StatusOK, "ok", "ok"},
		{StatusFailed, "failed", "failed"},
		{StatusInterrupted, "interrupted", "interrupted"},
		{StatusSkipped, "skipped", "skipped"},
	} {
		if got := tc.s.Label(); got != tc.label {
			t.Errorf("Status(%q).Label() = %q, want %q", tc.s, got, tc.label)
		}
		if got := tc.s.Value(); got != tc.value {
			t.Errorf("Status(%q).Value() = %q, want %q", tc.s, got, tc.value)
		}
		if got := target("x.example", tc.s, "", false, scan.Event{}).Status; got != tc.value {
			t.Errorf("target status %q: report says %q, want %q", tc.s, got, tc.value)
		}
	}
}

// TestTargetReportsEveryStatsField is the drift guard of #162: a field added
// to scan.Stats that the run-quality report ignores fails here, unless it is
// listed as deliberately unreported.
func TestTargetReportsEveryStatsField(t *testing.T) {
	unreported := map[string]bool{
		"RootDone": true, // the -resume point, kept in the state file
		// The names themselves go to the -inconclusive file (#217); the
		// outcomes already count them.
		"Inconclusive": true,
		// What a -resume repeats; the CLI takes it off before the report (#341).
		"Repeat": true,
	}
	// Skipped and Wildcard are set so Expired and Fingerprint show.
	base := scan.Stats{Skipped: 1, Wildcard: true}
	summary := func(s scan.Stats) any {
		return target("example.com", "ok", "", true, scan.Event{Kind: scan.EventDone, Stats: s})
	}
	want := summary(base)
	st := reflect.TypeOf(base)
	for i := range st.NumField() {
		name := st.Field(i).Name
		if unreported[name] {
			continue
		}
		s := base
		f := reflect.ValueOf(&s).Elem().Field(i)
		switch f.Kind() {
		case reflect.Int64:
			f.SetInt(f.Int() + 1)
		case reflect.Bool:
			f.SetBool(!f.Bool())
		case reflect.Slice:
			f.Set(reflect.Append(f, reflect.ValueOf(dns.Record{Type: "A", Value: "192.0.2.1"})))
		default:
			t.Fatalf("scan.Stats.%s: unhandled kind %s", name, f.Kind())
		}
		if reflect.DeepEqual(summary(s), want) {
			t.Errorf("scan.Stats.%s does not reach the run-quality report", name)
		}
	}
}
