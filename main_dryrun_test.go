package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"golang.org/x/net/dns/dnsmessage"
)

// dryRunPlans runs subenum -dry-run -format json and decodes its plan.
func dryRunPlans(t *testing.T, args ...string) (int, []dryRunTarget) {
	t.Helper()
	code, stdout := runCLI(t, "", append([]string{"-dry-run", "-format", "json", "-progress=false"}, args...)...)
	var plans []dryRunTarget
	if err := json.Unmarshal([]byte(stdout), &plans); err != nil {
		t.Fatalf("dry run output is not a JSON plan: %v\n%s", err, stdout)
	}
	return code, plans
}

// TestDryRunPlan is #192's done-when: candidates after dedupe, invalid
// entries and -exclude, query and duration estimates, and no results file.
func TestDryRunPlan(t *testing.T) {
	wl := writeFile(t, "wl.txt", "www\nwww\napi\nmail\nbad_label!\ndev\n")
	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")

	code, plans := dryRunPlans(t, "-simulate", "-w", wl, "-exclude", "dev.example.com",
		"-type", "A,AAAA", "-attempts", "3", "-rate", "4", "-o", out, "example.com")
	if code != exitOK {
		t.Fatalf("exit %d, want 0", code)
	}
	if len(plans) != 1 {
		t.Fatalf("got %d plans, want 1", len(plans))
	}
	p := plans[0]
	want := dryRunTarget{Domain: "example.com", Candidates: 3, Duplicates: 1, Skipped: 1, Excluded: 1,
		Queries: 6, QueriesMax: 18, Seconds: 1.5, SecondsMax: 4.5, PreflightOK: true}
	if p != want {
		t.Errorf("plan = %+v\nwant   %+v", p, want)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("a dry run wrote files: %v", left)
	}
}

func TestDryRunMaxQueriesCapsEstimate(t *testing.T) {
	wl := writeFile(t, "wl.txt", e2eWords)
	_, plans := dryRunPlans(t, "-simulate", "-w", wl, "-max-queries", "2", "-type", "A", "example.com")
	if len(plans) != 1 || plans[0].Candidates != 6 || plans[0].Queries != 2 {
		t.Fatalf("plans = %+v, want 6 candidates and 2 queries", plans)
	}
}

// TestDryRunCountsCNAMEQueries covers #223 and #249: a CNAME lookup sends one
// query of its own, and the estimate says so, as -rate charges it.
func TestDryRunCountsCNAMEQueries(t *testing.T) {
	wl := writeFile(t, "wl.txt", "www\napi\n")
	_, plans := dryRunPlans(t, "-simulate", "-w", wl, "-type", "A,AAAA,CNAME", "example.com")
	if len(plans) != 1 || plans[0].Queries != 2*3 {
		t.Fatalf("plans = %+v, want 6 queries: 2 names x (A 1 + AAAA 1 + CNAME 1)", plans)
	}
}

// TestDryRunPreflight: the preflight is a dry run's only DNS traffic, and a
// resolver that fails it fails the run.
func TestDryRunPreflight(t *testing.T) {
	wl := writeFile(t, "wl.txt", e2eWords)
	for _, tc := range []struct {
		name  string
		reply dnsserver.Reply
		code  int
		want  string
		ok    bool
	}{
		{"answers", dnsserver.Reply{A: []string{"192.0.2.1"}}, exitOK, "found", true},
		{"servfail", dnsserver.ServFail, exitFailure, "error", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := dnsserver.Listen(dnsserver.Options{}, func(dnsserver.Query) dnsserver.Reply { return tc.reply })
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			// The server answers at once; the timeout only has to cover the
			// stub resolver's own SERVFAIL retry, even on a loaded machine
			// (#235).
			code, plans := dryRunPlans(t, "-dns-server", srv.Addr, "-timeout", "2000", "-attempts", "1",
				"-type", "A", "-w", wl, "example.com")
			if code != tc.code {
				t.Errorf("exit %d, want %d", code, tc.code)
			}
			if len(plans) != 1 || plans[0].Preflight != tc.want || plans[0].PreflightOK != tc.ok {
				t.Fatalf("plans = %+v, want preflight %q ok=%v", plans, tc.want, tc.ok)
			}
			// The stub resolver may retry a SERVFAIL itself, as in a scan's
			// preflight; every query must still be the apex's.
			if apex, all := srv.QueriesFor("example.com", dnsmessage.TypeA), srv.Queries(); apex == 0 || apex != all {
				t.Errorf("dry run sent %d queries, %d of them the apex preflight; want only the preflight", all, apex)
			}
		})
	}
}

func TestDryRunText(t *testing.T) {
	wl := writeFile(t, "wl.txt", e2eWords)
	code, stdout := runCLI(t, "", "-dry-run", "-simulate", "-progress=false", "-w", wl, "-permute", "example.com")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"example.com", "candidates  6", "not bounded by -rate"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("text plan lacks %q:\n%s", want, stdout)
		}
	}
}
