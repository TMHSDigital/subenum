package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
		Queries: 6, QueriesMax: 18, RateEffective: 4, Seconds: 1.5, SecondsMax: 4.5, PreflightOK: true}
	if !reflect.DeepEqual(p, want) {
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
			srv, err := dnsserver.Listen(dnsserver.Options{CountNames: true}, func(dnsserver.Query) dnsserver.Reply { return tc.reply })
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			// The server answers at once; the timeout only has to cover the
			// stub resolver's own SERVFAIL retry, even on a loaded machine
			// (#235, #289).
			code, plans := dryRunPlans(t, "-dns-server", srv.Addr, "-timeout", "10000", "-attempts", "1",
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

// TestDryRunOutOfScopeTarget covers #372: a target -exclude rules out, by
// name or as a branch, is planned as out of scope and its preflight is not
// sent, while the other targets' preflights still are, paced by -rate.
func TestDryRunOutOfScopeTarget(t *testing.T) {
	srv, err := dnsserver.Listen(dnsserver.Options{CountNames: true}, func(dnsserver.Query) dnsserver.Reply {
		return dnsserver.Reply{A: []string{"192.0.2.1"}}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	wl := writeFile(t, "wl.txt", e2eWords)
	dl := writeFile(t, "targets.txt", "example.com\nexample.org\nexample.net\nexample.edu\n")
	start := time.Now()
	code, plans := dryRunPlans(t, "-dns-server", srv.Addr, "-timeout", "10000", "-attempts", "1", "-type", "A",
		"-rate", "2", "-exclude", "example.org,*.example.net", "-w", wl, "-dL", dl)
	elapsed := time.Since(start)
	if code != exitOK || len(plans) != 4 {
		t.Fatalf("exit %d, %d plans; want 0 and 4: %+v", code, len(plans), plans)
	}
	for _, p := range plans {
		out := p.Domain == "example.org" || p.Domain == "example.net"
		if p.OutOfScope != out || out && (p.Candidates != 0 || p.Queries != 0 || p.Preflight != "") {
			t.Errorf("plan %+v: want out_of_scope=%v, and no candidates or preflight when out of scope", p, out)
		}
		if n := srv.QueriesFor(p.Domain, dnsmessage.TypeA); (n == 0) != out {
			t.Errorf("%s: %d preflight queries; want none only when out of scope", p.Domain, n)
		}
	}
	if all := srv.Queries(); all != 2 {
		t.Errorf("dry run sent %d queries, want 2 (one preflight per in-scope target)", all)
	}
	// Two preflights at -rate 2 are half a second apart.
	if elapsed < 400*time.Millisecond {
		t.Errorf("two preflights at -rate 2 took %s; -rate did not pace them", elapsed)
	}
	_, stdout := runCLI(t, "", "-dry-run", "-simulate", "-progress=false", "-exclude", "example.com", "-w", wl, "example.com")
	if !strings.Contains(stdout, "out of scope under -exclude") || strings.Contains(stdout, "candidates") {
		t.Errorf("text plan does not mark the target out of scope:\n%s", stdout)
	}
}

// TestDryRunResolverPool covers #376: with -r, the plan preflights every
// pool member with the target's own query, reports a failing member without
// failing the run, and bounds the duration by -rate-per-resolver times the
// pool's size when that is below -rate.
func TestDryRunResolverPool(t *testing.T) {
	listen := func(reply dnsserver.Reply) *dnsserver.Server {
		srv, err := dnsserver.Listen(dnsserver.Options{CountNames: true}, func(dnsserver.Query) dnsserver.Reply { return reply })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(srv.Close)
		return srv
	}
	answers := dnsserver.Reply{A: []string{"192.0.2.1"}}
	trusted, good, bad := listen(answers), listen(answers), listen(dnsserver.ServFail)
	wl := writeFile(t, "wl.txt", e2eWords)
	list := writeFile(t, "resolvers.txt", good.Addr+"\n"+bad.Addr+"\n")
	args := []string{"-dns-server", trusted.Addr, "-r", list, "-rate-per-resolver", "3", "-timeout", "10000",
		"-attempts", "1", "-type", "A", "-w", wl}

	for _, tc := range []struct {
		rate string
		want int
	}{{"0", 6}, {"4", 4}} {
		code, plans := dryRunPlans(t, append(args, "-rate", tc.rate, "example.com")...)
		if code != exitOK || len(plans) != 1 {
			t.Fatalf("-rate %s: exit %d, %d plans; want 0 and 1 (a failing pool member does not fail the run)", tc.rate, code, len(plans))
		}
		p := plans[0]
		if p.RateEffective != tc.want || p.Seconds != float64(p.Queries)/float64(tc.want) {
			t.Errorf("-rate %s: rate_effective %d, seconds %v; want %d/s for %d queries", tc.rate, p.RateEffective, p.Seconds, tc.want, p.Queries)
		}
		want := []dryRunResolver{{Addr: good.Addr, Preflight: "found", OK: true}, {Addr: bad.Addr, Preflight: "error"}}
		if !p.PreflightOK || !reflect.DeepEqual(p.PoolPreflight, want) {
			t.Errorf("-rate %s: preflight ok=%v, pool preflight %+v; want ok and %+v", tc.rate, p.PreflightOK, p.PoolPreflight, want)
		}
	}
	for _, srv := range []*dnsserver.Server{good, bad} {
		if apex, all := srv.QueriesFor("example.com", dnsmessage.TypeA), srv.Queries(); apex == 0 || apex != all {
			t.Errorf("pool member %s got %d queries, %d of them the apex preflight; want only the preflight", srv.Addr, all, apex)
		}
	}

	_, stdout := runCLI(t, "", append(args, "-dry-run", "-progress=false", "example.com")...)
	for _, want := range []string{"at 6/s (-rate-per-resolver 3 x 2 resolvers)", "pool        ok via " + good.Addr + ": found",
		"pool        FAILED via " + bad.Addr + ": error"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("text plan lacks %q:\n%s", want, stdout)
		}
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
