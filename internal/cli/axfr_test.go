package cli

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/axfr"
	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// axfrZone serves example.test from one local server: ns1 is its name server
// and resolves to the server itself, so the transfer goes to it too. allow
// decides whether AXFR is allowed, and denial ("", "nsec", "nsec3") how its
// negative answers are signed.
func axfrZone(t *testing.T, allow bool, denial string) *dnstest.Server {
	t.Helper()
	found := map[string]bool{"example.test": true, "www.example.test": true, "admin-legacy.example.test": true}
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Type == dnsmessage.TypeAXFR && q.Name == "example.test":
			if !allow {
				return dnstest.Refused
			}
			return dnstest.Reply{Transfer: []string{"www.example.test", "admin-legacy.example.test", "gone.example.test"}}
		case q.Type == dnsmessage.TypeNS && q.Name == "example.test":
			return dnstest.Reply{NS: []string{"ns1.example.test"}}
		case q.Name == "ns1.example.test":
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"127.0.0.1"}}
			}
			return dnstest.Reply{}
		case found[q.Name] && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"192.0.2.10"}}
		case found[q.Name]:
			return dnstest.Reply{}
		}
		return dnstest.Reply{RCode: dnsmessage.RCodeNameError, Denial: denial}
	})
	return srv
}

// runAXFR runs the CLI against srv with zone transfers asked on its port,
// stdout and stderr merged.
func runAXFR(t *testing.T, srv *dnstest.Server, args ...string) (int, string) {
	t.Helper()
	_, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	return runCLIMergedWith(t, runArgs{axfrPort: port, args: localArgs(args...)})
}

// TestE2EZoneTransfer covers #85: a name server that allows AXFR gives
// names the wordlist lacks, each still verified by resolution (gone. is in
// the zone but does not resolve), and the report names the server.
func TestE2EZoneTransfer(t *testing.T) {
	t.Parallel()
	srv := axfrZone(t, true, "")
	wl := writeFile(t, "wl.txt", "www\nmail\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	code, out := runAXFR(t, srv, "-axfr", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl, "example.test")
	if code != 0 || !strings.Contains(out, "admin-legacy.example.test") {
		t.Fatalf("exit %d: the transferred name was not found\n%s", code, out)
	}
	if !strings.Contains(out, "allowed AXFR") {
		t.Errorf("no zone transfer finding on stderr\n%s", out)
	}
	if strings.Contains(out, "\ngone.example.test") {
		t.Errorf("an unresolvable transferred name was reported\n%s", out)
	}
	if n := srv.QueriesFor("example.test", dnsmessage.TypeAXFR); n != 1 {
		t.Errorf("AXFR queries = %d, want 1", n)
	}
	var s output.Summary
	data, err := os.ReadFile(stats)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	tg := s.Targets[0]
	if !slices.Equal(tg.AXFRAllowed, []string{"ns1.example.test"}) || tg.AXFRNames != 3 {
		t.Errorf("report axfr_allowed = %q, axfr_names = %d; want ns1.example.test and 3", tg.AXFRAllowed, tg.AXFRNames)
	}
	if tg.AXFRFound != 2 { // www and admin-legacy resolve, gone does not (#273)
		t.Errorf("report axfr_found = %d, want 2", tg.AXFRFound)
	}
}

// TestE2EZoneTransferRefused: a refusal, the correct configuration, is not
// an error and leaves the scan to the wordlist.
func TestE2EZoneTransferRefused(t *testing.T) {
	t.Parallel()
	srv := axfrZone(t, false, "nsec3")
	wl := writeFile(t, "wl.txt", "www\nmail\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	code, out := runAXFR(t, srv, "-axfr", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl, "example.test")
	if code != 0 || !strings.Contains(out, "www.example.test") || strings.Contains(out, "admin-legacy") {
		t.Fatalf("exit %d; want the wordlist scan only\n%s", code, out)
	}
	if strings.Contains(out, "allowed AXFR") || strings.Contains(out, "Warning") {
		t.Errorf("a refused transfer was reported as a finding or a problem\n%s", out)
	}
	var s output.Summary
	data, _ := os.ReadFile(stats)
	_ = json.Unmarshal(data, &s)
	if tg := s.Targets[0]; len(tg.AXFRAllowed) != 0 || tg.AXFRError != "" || tg.ZoneDenial != "nsec3" {
		t.Errorf("report axfr_allowed = %q, axfr_error = %q, zone_denial = %q; want neither, and nsec3", tg.AXFRAllowed, tg.AXFRError, tg.ZoneDenial)
	}
	if strings.Contains(out, "Zone walkable") {
		t.Errorf("an NSEC3 zone was reported walkable\n%s", out)
	}
}

// TestE2EZoneWalkable covers #234: a zone signed with plain NSEC is reported
// walkable even when its servers refuse transfers, with the probe counted.
func TestE2EZoneWalkable(t *testing.T) {
	t.Parallel()
	srv := axfrZone(t, false, "nsec")
	wl := writeFile(t, "wl.txt", "www\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	code, out := runAXFR(t, srv, "-axfr", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl, "example.test")
	if code != 0 || !strings.Contains(out, "Zone walkable") {
		t.Fatalf("exit %d; want a walkable-zone finding\n%s", code, out)
	}
	var s output.Summary
	data, err := os.ReadFile(stats)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	if tg := s.Targets[0]; tg.ZoneDenial != "nsec" {
		t.Errorf("zone_denial = %q, want nsec", tg.ZoneDenial)
	}
}

// nsZone serves example.test from one local server. hosts are its name
// servers and the addresses each resolves to; one with no addresses does not
// resolve. transfer is the zone an AXFR gives, nil to refuse it. www and the
// transferred names resolve.
func nsZone(t *testing.T, hosts map[string][]string, transfer []string) *dnstest.Server {
	t.Helper()
	return dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		addrs, isNS := hosts[q.Name]
		switch {
		case q.Type == dnsmessage.TypeAXFR && q.Name == "example.test":
			if transfer == nil {
				return dnstest.Refused
			}
			return dnstest.Reply{Transfer: transfer}
		case q.Type == dnsmessage.TypeNS && q.Name == "example.test":
			return dnstest.Reply{NS: slices.Sorted(maps.Keys(hosts))}
		case isNS && len(addrs) == 0:
			return dnstest.NXDomain
		case isNS && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: addrs}
		case q.Name == "www.example.test" || slices.Contains(transfer, q.Name):
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"192.0.2.10"}}
			}
		default:
			return dnstest.NXDomain
		}
		return dnstest.Reply{}
	})
}

// axfrSummary reads the -stats report a run wrote.
func axfrSummary(t *testing.T, path string) output.Summary {
	t.Helper()
	var s output.Summary
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Targets) != 1 {
		t.Fatalf("report has %d targets, want 1", len(s.Targets))
	}
	return s
}

// TestE2EZoneTransferNSLookupFails covers #303: when the target's name
// servers cannot be found, the run warns, records why in the report, asks no
// one for a transfer and still scans the wordlist.
func TestE2EZoneTransferNSLookupFails(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		ns   dnstest.Reply
		want string
	}{
		"servfail": {dnstest.ServFail, "name server lookup failed"},
		// The resolver reports an answer without NS records as a not-found
		// error, which is worded as such (#347).
		"no NS":    {dnstest.Reply{}, "no name servers found for example.test"},
		"nxdomain": {dnstest.NXDomain, "no name servers found for example.test"},
	} {
		srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
			switch {
			case q.Type == dnsmessage.TypeNS:
				return tc.ns
			case q.Name == "www.example.test" && q.Type == dnsmessage.TypeA:
				return dnstest.Reply{A: []string{"192.0.2.10"}}
			}
			return dnstest.NXDomain
		})
		wl := writeFile(t, "wl.txt", "www\nmail\n")
		stats := filepath.Join(t.TempDir(), "run.json")
		code, out := runAXFR(t, srv, "-axfr", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl, "example.test")
		if code != 0 || !strings.Contains(out, "www.example.test") {
			t.Errorf("%s: exit %d; want the wordlist scan to run\n%s", name, code, out)
			continue
		}
		if !strings.Contains(out, "Warning: -axfr: "+tc.want) {
			t.Errorf("%s: no warning with %q\n%s", name, tc.want, out)
		}
		if tg := axfrSummary(t, stats).Targets[0]; !strings.HasPrefix(tg.AXFRError, tc.want) || len(tg.AXFRAllowed) != 0 {
			t.Errorf("%s: report axfr_error = %q, axfr_allowed = %q; want an error starting %q and no server", name, tg.AXFRError, tg.AXFRAllowed, tc.want)
		}
		if n := srv.QueriesFor("example.test", dnsmessage.TypeAXFR); n != 0 {
			t.Errorf("%s: AXFR queries = %d, want 0", name, n)
		}
	}
}

// TestE2EZoneTransferServerCap covers #303: of a target's ten name servers,
// all refusing, only axfr.MaxServers are resolved and asked.
func TestE2EZoneTransferServerCap(t *testing.T) {
	t.Parallel()
	hosts := map[string][]string{}
	for i := range 10 {
		hosts["ns"+strconv.Itoa(i)+".example.test"] = []string{"127.0.0.1"}
	}
	srv := nsZone(t, hosts, nil)
	wl := writeFile(t, "wl.txt", "www\n")
	code, out := runAXFR(t, srv, "-axfr", "-v", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-w", wl, "example.test")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if n := srv.QueriesFor("example.test", dnsmessage.TypeAXFR); n != axfr.MaxServers {
		t.Errorf("AXFR queries = %d, want %d", n, axfr.MaxServers)
	}
	resolved := 0
	for host := range hosts {
		if srv.QueriesFor(host, dnsmessage.TypeA) > 0 {
			resolved++
		}
	}
	if resolved != axfr.MaxServers {
		t.Errorf("%d name servers were resolved, want %d", resolved, axfr.MaxServers)
	}
	if want := "(" + strconv.Itoa(axfr.MaxServers) + " addresses asked)"; !strings.Contains(out, want) {
		t.Errorf("verbose output lacks %q\n%s", want, out)
	}
}

// TestE2EZoneTransferAddressCap covers #303: a name server with four
// addresses, all refusing, is asked on axfr.AddrsPerServer of them.
func TestE2EZoneTransferAddressCap(t *testing.T) {
	t.Parallel()
	srv := nsZone(t, map[string][]string{"ns1.example.test": {"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}}, nil)
	wl := writeFile(t, "wl.txt", "www\n")
	code, out := runAXFR(t, srv, "-axfr", "-v", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-w", wl, "example.test")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if n := srv.QueriesFor("example.test", dnsmessage.TypeAXFR); n != axfr.AddrsPerServer {
		t.Errorf("AXFR queries = %d, want %d", n, axfr.AddrsPerServer)
	}
	if want := "(" + strconv.Itoa(axfr.AddrsPerServer) + " addresses asked)"; !strings.Contains(out, want) {
		t.Errorf("verbose output lacks %q\n%s", want, out)
	}
}

// TestE2EZoneTransferSkipsUnresolvableServer covers #303: a name server that
// does not resolve is skipped, mentioned only under -v, and the transfer
// still comes from the one that does.
func TestE2EZoneTransferSkipsUnresolvableServer(t *testing.T) {
	t.Parallel()
	srv := nsZone(t, map[string][]string{"ns-bad.example.test": nil, "ns1.example.test": {"127.0.0.1"}},
		[]string{"www.example.test", "admin-legacy.example.test"})
	wl := writeFile(t, "wl.txt", "www\n")
	const skipped = "cannot resolve name server ns-bad.example.test"
	for _, verbose := range []bool{false, true} {
		args := []string{"-axfr", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-w", wl}
		if verbose {
			args = append(args, "-v")
		}
		code, out := runAXFR(t, srv, append(args, "example.test")...)
		if code != 0 || !strings.Contains(out, "admin-legacy.example.test") || !strings.Contains(out, "ns1.example.test (127.0.0.1) allowed AXFR") {
			t.Errorf("verbose %v: exit %d; want the transfer from ns1\n%s", verbose, code, out)
		}
		if strings.Contains(out, skipped) != verbose {
			t.Errorf("verbose %v: output mentions the unresolvable server = %v\n%s", verbose, !verbose, out)
		}
	}
}

// TestE2EZoneTransferOutOfScopeTarget covers #372: a target -exclude rules
// out, by name or as a branch, is refused before -axfr or -ct asks anyone
// anything about it.
func TestE2EZoneTransferOutOfScopeTarget(t *testing.T) {
	t.Parallel()
	var ctHits atomic.Int64
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ctHits.Add(1)
		_, _ = w.Write([]byte("[]"))
	}))
	defer ct.Close()
	wl := writeFile(t, "wl.txt", "www\n")
	for _, exclude := range []string{"example.test", "*.example.test"} {
		srv := axfrZone(t, true, "")
		_, port, err := net.SplitHostPort(srv.Addr)
		if err != nil {
			t.Fatal(err)
		}
		code, out := runCLIMergedWith(t, runArgs{axfrPort: port, sourceURLs: map[string]string{"ct": ct.URL + "/"},
			args: localArgs("-axfr", "-ct", "-exclude", exclude, "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-w", wl, "example.test")})
		if code == exitOK || !strings.Contains(out, "out of scope") {
			t.Errorf("-exclude %s: exit %d; want the target refused\n%s", exclude, code, out)
		}
		if n := srv.Queries(); n != 0 {
			t.Errorf("-exclude %s: %d DNS queries for an out-of-scope target, want 0\n%s", exclude, n, out)
		}
	}
	if n := ctHits.Load(); n != 0 {
		t.Errorf("-ct was asked %d times about an out-of-scope target, want 0", n)
	}
}

// TestE2EZoneTransferSkipsExcludedServer covers #372: a name server -exclude
// rules out is neither resolved nor asked for a transfer; the in-scope one
// still is.
func TestE2EZoneTransferSkipsExcludedServer(t *testing.T) {
	t.Parallel()
	srv := nsZone(t, map[string][]string{"ns1.example.test": {"127.0.0.1"}, "ns2.corp.example.test": {"127.0.0.1"}},
		[]string{"www.example.test", "admin-legacy.example.test"})
	wl := writeFile(t, "wl.txt", "www\n")
	code, out := runAXFR(t, srv, "-axfr", "-v", "-exclude", "*.corp.example.test", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-w", wl, "example.test")
	if code != exitOK || !strings.Contains(out, "ns1.example.test (127.0.0.1) allowed AXFR") {
		t.Fatalf("exit %d; want the transfer from ns1\n%s", code, out)
	}
	for _, qt := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		if n := srv.QueriesFor("ns2.corp.example.test", qt); n != 0 {
			t.Errorf("the excluded name server got %d %v lookups, want 0", n, qt)
		}
	}
	if n := srv.QueriesFor("example.test", dnsmessage.TypeAXFR); n != 1 {
		t.Errorf("AXFR queries = %d, want 1 (ns1 only)", n)
	}
	if !strings.Contains(out, "skipping name server ns2.corp.example.test: it is out of scope") {
		t.Errorf("-v does not say the excluded name server was skipped\n%s", out)
	}
}

// TestE2EResumeReusesZoneTransfer covers #303: a resumed run scans the names
// the interrupted run's transfer gave and asks no name server again, so its
// candidate list is the one the saved position counts in.
func TestE2EResumeReusesZoneTransfer(t *testing.T) {
	t.Parallel()
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Type == dnsmessage.TypeAXFR:
			return dnstest.Reply{Transfer: []string{"other.example.test"}}
		case q.Type == dnsmessage.TypeNS:
			return dnstest.Reply{NS: []string{"ns1.example.test"}}
		case q.Name == "ns1.example.test" && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"127.0.0.1"}}
		case q.Name == "example.test" || q.Name == "ns1.example.test":
			return dnstest.Reply{}
		case slices.Contains([]string{"zt1.example.test", "zt2.example.test", "other.example.test", "www.example.test"}, q.Name):
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"192.0.2.10"}}
			}
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	_, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	wl := writeFile(t, "wl.txt", "www\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	args := append(localArgs("-axfr", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl), "example.test")
	path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{{
		Domain: "example.test", AXFRDone: true, AXFR: []string{"zt1", "zt2"}, AXFRServers: []string{"ns1.example.test"},
	}}})
	code, out := runCLIMergedWith(t, runArgs{axfrPort: port, args: []string{"-resume", path}})
	if code != 0 || !strings.Contains(out, "zt1.example.test") || !strings.Contains(out, "zt2.example.test") {
		t.Fatalf("exit %d; want the saved transfer's names scanned\n%s", code, out)
	}
	if strings.Contains(out, "other.example.test") {
		t.Errorf("the resumed run scanned a name from a new transfer\n%s", out)
	}
	if ns, axfr := srv.QueriesFor("example.test", dnsmessage.TypeNS), srv.QueriesFor("example.test", dnsmessage.TypeAXFR); ns != 0 || axfr != 0 {
		t.Errorf("the resumed run sent %d NS and %d AXFR queries, want none", ns, axfr)
	}
	if tg := axfrSummary(t, stats).Targets[0]; !slices.Equal(tg.AXFRAllowed, []string{"ns1.example.test"}) || tg.AXFRNames != 2 {
		t.Errorf("report axfr_allowed = %q, axfr_names = %d; want the saved ns1.example.test and 2", tg.AXFRAllowed, tg.AXFRNames)
	}
}

// TestResumeFinishedTargetKeepsDetails covers #315: the report of a resumed
// run keeps the zone transfer and -permute pass of a target that finished
// before the interrupt, and the target triggers no new transfer, even when
// its state lacks one.
func TestResumeFinishedTargetKeepsDetails(t *testing.T) {
	t.Parallel()
	for name, axfrDone := range map[string]bool{"transfer saved": true, "transfer missing": false} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
				switch q.Type {
				case dnsmessage.TypeAXFR:
					return dnstest.Reply{Transfer: []string{"other.example.test"}}
				case dnsmessage.TypeNS:
					return dnstest.Reply{NS: []string{"ns1.example.test"}}
				}
				return dnstest.NXDomain
			})
			_, port, err := net.SplitHostPort(srv.Addr)
			if err != nil {
				t.Fatal(err)
			}
			wl := writeFile(t, "wl.txt", "www\n")
			stats := filepath.Join(t.TempDir(), "run.json")
			args := append(localArgs("-axfr", "-permute", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl), "example.test")
			permuted := scan.Stats{NXDomain: 7}
			target := resumeTarget{
				Domain: "example.test", Done: true, RootDone: 1, Processed: 1, Total: 1, Stats: scan.Stats{Found: 1},
				Results: []output.Result{{Result: scan.Result{Subdomain: "www.example.test"}}},
				Permute: &resumePass{RootDone: 7, Stats: permuted, Processed: 7, Total: 7},
			}
			if axfrDone {
				target.AXFRDone, target.AXFR, target.AXFRServers = true, []string{"zt1", "zt2"}, []string{"ns1.example.test"}
			}
			path := writeState(t, resumeState{Args: args, Targets: []resumeTarget{target}})
			code, out := runCLIMergedWith(t, runArgs{axfrPort: port, args: []string{"-resume", path}})
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			if ns, axfr := srv.QueriesFor("example.test", dnsmessage.TypeNS), srv.QueriesFor("example.test", dnsmessage.TypeAXFR); ns != 0 || axfr != 0 {
				t.Errorf("the finished target caused %d NS and %d AXFR queries, want none", ns, axfr)
			}
			tg := axfrSummary(t, stats).Targets[0]
			wantAllowed, wantNames := []string(nil), 0
			if axfrDone {
				wantAllowed, wantNames = []string{"ns1.example.test"}, 2
			}
			if !slices.Equal(tg.AXFRAllowed, wantAllowed) || tg.AXFRNames != wantNames {
				t.Errorf("report axfr_allowed = %q, axfr_names = %d; want %q and %d", tg.AXFRAllowed, tg.AXFRNames, wantAllowed, wantNames)
			}
			// The seeds are the found name and, as in the live run, the
			// transferred names, which are also candidates.
			seeds := []string{"www"}
			if axfrDone {
				seeds = append(seeds, "zt1", "zt2")
			}
			want, _, _ := candidates.Permutations("example.test", seeds, seeds)
			if p := tg.Permutation; p == nil || p.Seeds != len(seeds) || p.Candidates != len(want) || p.Processed != 7 || p.Verdict != scan.VerdictComplete {
				t.Errorf("report permutation = %+v; want %d seeds, %d candidates, 7 processed, complete", p, len(seeds), len(want))
			}
		})
	}
}

// TestZoneTransferStopsWhenCancelled covers #303: once the run is cancelled,
// a name server's next address is not asked.
func TestZoneTransferStopsWhenCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Type == dnsmessage.TypeAXFR:
			cancel() // the interrupt arrives during the first transfer
			return dnstest.Refused
		case q.Type == dnsmessage.TypeNS:
			return dnstest.Reply{NS: []string{"ns1.example.test"}}
		case q.Name == "ns1.example.test" && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"127.0.0.1", "127.0.0.1"}}
		case q.Name == "ns1.example.test":
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	_, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	out := output.New(nil, false, output.FormatText)
	out.SetStderr(io.Discard)
	res := zoneTransfer(ctx, cliFlags{timeoutMs: 5000, dnsServer: srv.Addr, axfr: true}, port, "example.test", nil, out.Info, nil, time.Time{})
	if res.tried != 1 {
		t.Errorf("addresses asked = %d, want 1: the second came after the cancel", res.tried)
	}
	if n := srv.QueriesFor("example.test", dnsmessage.TypeAXFR); n != 1 {
		t.Errorf("AXFR queries = %d, want 1", n)
	}
}

// TestE2ELabAXFR covers #434: in lab mode -axfr asks the lab server, so a
// scenario with $TRANSFER allow gives its names with source axfr, and one
// without it refuses the transfer. Lab 7's name server address is in
// TEST-NET, which a transfer sent to it could not reach. Simulation still
// ignores -axfr with a note.
func TestE2ELabAXFR(t *testing.T) {
	t.Parallel()
	code, out := runCLIMerged(t, "-axfr", "-simulate-zone", "lab7", "-format", "jsonl", "-progress=false", "lab.example")
	got := seenResults(t, lastJSONLines(out))
	if code != exitOK || !slices.Equal(got["billing-legacy.lab.example"].Sources, []string{"axfr"}) || !strings.Contains(out, "allowed AXFR of lab.example") {
		t.Errorf("lab7: exit %d, results %v\n%s", code, got, out)
	}

	refusing := writeFile(t, "refuse.zone", "@ NS ns1\nns1 A 192.0.2.53\nwww A 192.0.2.10\nhidden A 192.0.2.11\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	code, out = runCLIMerged(t, "-axfr", "-simulate-zone", refusing, "-w", writeFile(t, "w.txt", "www\n"), "-stats", stats, "-progress=false", "lab.example")
	if code != exitOK || strings.Contains(out, "hidden.lab.example") || strings.Contains(out, "allowed AXFR") {
		t.Errorf("without $TRANSFER allow: exit %d\n%s", code, out)
	}
	if b, err := os.ReadFile(stats); err != nil || strings.Contains(string(b), "axfr_allowed") {
		t.Errorf("without $TRANSFER allow the report lists a server that allowed it: %s %v", b, err)
	}
	wl := writeFile(t, "wl.txt", "www\n")
	if code, out := runCLIMerged(t, "-axfr", "-simulate", "-seed", "1", "-progress=false", "-w", wl, "example.com"); code != 0 || !strings.Contains(out, "-axfr is ignored in simulation mode") {
		t.Errorf("simulate: exit %d\n%s", code, out)
	}
}

// lastJSONLines keeps the lines of merged output that are JSON objects.
func lastJSONLines(out string) string {
	var b strings.Builder
	for line := range strings.Lines(out) {
		if strings.HasPrefix(line, "{") {
			b.WriteString(line)
		}
	}
	return b.String()
}
