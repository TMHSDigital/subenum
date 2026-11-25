package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/output"
)

// TestE2EFollowRecords covers #432's acceptance: with -follow-records, a
// name only a CNAME names is reported with source records and counted in
// -stats; without the flag the output is unchanged; an excluded target is
// never queried.
func TestE2EFollowRecords(t *testing.T) {
	t.Parallel()
	var corpAsked atomic.Bool
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "mx.corp.example.com":
			corpAsked.Store(true)
			return dnstest.NXDomain
		case "example.com":
			return dnstest.Reply{}
		case "app.example.com":
			return dnstest.Reply{CNAME: "lb-7.int.example.com", A: []string{"192.0.2.7"}}
		case "lb-7.int.example.com":
			return dnstest.Reply{A: []string{"192.0.2.7"}}
		case "mail.example.com":
			return dnstest.Reply{MX: []string{"10 mx.corp.example.com"}, A: []string{"192.0.2.8"}}
		}
		return dnstest.NXDomain
	})
	wl := writeFile(t, "wl.txt", "app\nmail\n")
	run := func(extra ...string) (map[string][]string, output.Summary) {
		t.Helper()
		stats := filepath.Join(t.TempDir(), "run.json")
		args := append(localArgs(append([]string{"-dns-server", srv.Addr, "-type", "A,CNAME,MX", "-progress=false", "-format", "jsonl",
			"-w", wl, "-stats", stats, "-exclude", "*.corp.example.com"}, extra...)...), "example.com")
		code, out := runCLIWith(t, runArgs{args: args})
		if code != exitOK {
			t.Fatalf("exit %d\n%s", code, out)
		}
		sources := map[string][]string{}
		for name, r := range seenResults(t, out) {
			sources[name] = r.Sources
		}
		var s output.Summary
		b, err := os.ReadFile(stats)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		return sources, s
	}

	got, s := run("-follow-records")
	if !slices.Equal(got["lb-7.int.example.com"], []string{"records"}) || len(got) != 3 {
		t.Errorf("-follow-records: results %v, want lb-7.int with source records", got)
	}
	if s.Targets[0].RecordsFound != 1 || s.Verdict != "complete" {
		t.Errorf("-stats: records_found %d verdict %s", s.Targets[0].RecordsFound, s.Verdict)
	}
	if corpAsked.Load() {
		t.Error("the excluded MX target was queried")
	}

	got, s = run()
	if _, ok := got["lb-7.int.example.com"]; ok || len(got) != 2 || s.Targets[0].RecordsFound != 0 {
		t.Errorf("without -follow-records: results %v, records_found %d", got, s.Targets[0].RecordsFound)
	}

	// A run stopped after the wordlist, before its follow-up target was
	// tested, queues the target of the result it restores (#432).
	args := append(localArgs("-dns-server", srv.Addr, "-type", "A,CNAME", "-progress=false", "-format", "jsonl", "-w", wl, "-follow-records"), "example.com")
	app := output.Result{Sources: []string{"wordlist"}}
	app.Subdomain = "app.example.com"
	app.Records = []dns.Record{{Type: "CNAME", Value: "lb-7.int.example.com"}, {Type: "A", Value: "192.0.2.7"}}
	path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{{Domain: "example.com", RootDone: 2, Processed: 2, Results: []output.Result{app}}}})
	code, out := runCLIWith(t, runArgs{args: []string{"-resume", path}})
	resumed := seenResults(t, out)
	if code != exitOK || !slices.Equal(resumed["lb-7.int.example.com"].Sources, []string{"records"}) {
		t.Errorf("resumed: exit %d, results %v; want lb-7.int found as records", code, resumed)
	}
}

// TestE2EResumeFollowRecordsHit covers #441: a -follow-records hit saved
// before the interrupt keeps its records source when the run resumes, and
// counts in -stats's records_found as the uninterrupted run's does.
func TestE2EResumeFollowRecordsHit(t *testing.T) {
	t.Parallel()
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "example.com":
			return dnstest.Reply{}
		case "app.example.com":
			return dnstest.Reply{CNAME: "lb-7.int.example.com", A: []string{"192.0.2.7"}}
		case "lb-7.int.example.com":
			return dnstest.Reply{A: []string{"192.0.2.7"}}
		}
		return dnstest.NXDomain
	})
	wl := writeFile(t, "wl.txt", "app\n")
	stats := filepath.Join(t.TempDir(), "stats.json")
	args := append(localArgs("-dns-server", srv.Addr, "-type", "A,CNAME", "-progress=false", "-format", "jsonl",
		"-w", wl, "-follow-records", "-stats", stats), "example.com")
	app := output.Result{Sources: []string{"wordlist"}}
	app.Subdomain, app.Records = "app.example.com", []dns.Record{{Type: "CNAME", Value: "lb-7.int.example.com"}, {Type: "A", Value: "192.0.2.7"}}
	hit := output.Result{Sources: []string{"records"}}
	hit.Subdomain, hit.Records = "lb-7.int.example.com", []dns.Record{{Type: "A", Value: "192.0.2.7"}}
	path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{{Domain: "example.com", MainDone: true, RootDone: 1, Processed: 1, Total: 1,
		Results: []output.Result{app, hit}}}})
	code, out := runCLIWith(t, runArgs{args: []string{"-resume", path}})
	got := seenResults(t, out)
	if code != exitOK || !slices.Equal(got["lb-7.int.example.com"].Sources, []string{"records"}) || len(got) != 2 {
		t.Fatalf("resumed: exit %d, results %v; want lb-7.int restored with source records\n%s", code, got, out)
	}
	if !slices.Equal(got["app.example.com"].Sources, []string{"wordlist"}) {
		t.Errorf("resumed: app sources %v, want wordlist", got["app.example.com"].Sources)
	}
	var s output.Summary
	b, err := os.ReadFile(stats)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if s.Targets[0].RecordsFound != 1 {
		t.Errorf("-stats: records_found %d, want the restored record-follow hit counted", s.Targets[0].RecordsFound)
	}
}
