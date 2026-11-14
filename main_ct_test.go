package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/output"
)

// TestE2ECertificateTransparency covers #130: a name only CT knows is
// found, the report counts the CT names, and a CT outage is a warning, not
// a failed scan. Everything runs against local servers.
func TestE2ECertificateTransparency(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if (q.Name == "www.example.com" || q.Name == "legacy-billing.example.com") && q.Type == dnsmessage.TypeA {
			return dnstest.Reply{A: []string{"192.0.2.10"}}
		}
		if q.Name == "www.example.com" || q.Name == "legacy-billing.example.com" {
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	ctUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name_value": "legacy-billing.example.com\n*.www.example.com\nunrelated.org"}]`))
	}))
	defer ctUp.Close()
	ctDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ctDown.Close()
	t.Cleanup(func() { ctBaseURL = "" })

	wl := writeFile(t, "wl.txt", "www\nmail\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	scan := func(base string) (int, string, output.Summary) {
		ctBaseURL = base + "/"
		code, out := runCLI(t, "", "-ct", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl, "example.com")
		var s output.Summary
		if data, err := os.ReadFile(stats); err == nil {
			_ = json.Unmarshal(data, &s)
		}
		return code, out, s
	}

	code, out, s := scan(ctUp.URL)
	if code != 0 || !strings.Contains(out, "legacy-billing.example.com") {
		t.Fatalf("exit %d, results %q: the CT-only name was not found", code, out)
	}
	if got := s.Targets[0].CTNames; got != 2 { // legacy-billing and www
		t.Errorf("ct_names = %d, want 2", got)
	}

	code, out, s = scan(ctDown.URL)
	if code != 0 || !strings.Contains(out, "www.example.com") || strings.Contains(out, "legacy-billing") {
		t.Errorf("CT down: exit %d, results %q; want the wordlist scan only", code, out)
	}
	if s.Targets[0].CTError == "" {
		t.Error("CT down: the report has no ct_error")
	}
}

// TestE2EPassiveSources covers #193: -sources asks each source once, merges
// their names as candidates, and the report has an entry per source, a
// failed one included. -ct is short for -sources ct.
func TestE2EPassiveSources(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "www.example.com", "legacy-billing.example.com", "old-shop.example.com":
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"192.0.2.10"}}
			}
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	ctUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name_value": "legacy-billing.example.com"}]`))
	}))
	defer ctUp.Close()
	wayback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("http://old-shop.example.com/cart\nhttps://www.example.com/\n"))
	}))
	defer wayback.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	t.Cleanup(func() { ctBaseURL, waybackBaseURL = "", "" })

	wl := writeFile(t, "wl.txt", "www\nmail\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	report := func() output.TargetSummary {
		var s output.Summary
		data, err := os.ReadFile(stats)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &s); err != nil {
			t.Fatal(err)
		}
		return s.Targets[0]
	}

	ctBaseURL, waybackBaseURL = ctUp.URL+"/", wayback.URL
	code, out := runCLI(t, "", "-ct", "-sources", "wayback", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl, "example.com")
	if code != 0 || !strings.Contains(out, "legacy-billing.example.com") || !strings.Contains(out, "old-shop.example.com") {
		t.Fatalf("exit %d, results %q: want the CT and the Wayback name", code, out)
	}
	tg := report()
	if len(tg.Sources) != 2 || tg.Sources[0] != (output.SourceSummary{Name: "ct", Names: 1}) || tg.Sources[1] != (output.SourceSummary{Name: "wayback", Names: 2}) {
		t.Errorf("report sources = %+v, want ct 1 and wayback 2", tg.Sources)
	}
	if tg.CTNames != 1 {
		t.Errorf("ct_names = %d, want 1 (the ct entry, for compatibility)", tg.CTNames)
	}

	waybackBaseURL = down.URL
	code, out = runCLI(t, "", "-sources", "wayback,ct", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl, "example.com")
	if code != 0 || !strings.Contains(out, "legacy-billing.example.com") || strings.Contains(out, "old-shop") {
		t.Errorf("wayback down: exit %d, results %q; want the CT name only", code, out)
	}
	if tg := report(); len(tg.Sources) != 2 || tg.Sources[1].Name != "wayback" || tg.Sources[1].Error == "" {
		t.Errorf("wayback down: report sources = %+v, want a wayback error", tg.Sources)
	}

	if code, out := runCLIMerged(t, "-sources", "ct,shodan", "-w", wl, "example.com"); code != exitUsage || !strings.Contains(out, "shodan") {
		t.Errorf("unknown source: exit %d\n%s", code, out)
	}
}

// TestCandidates covers #248's shared set: names from several sources are
// added once, after the wordlist, and the shared -seeds map is never
// written to.
func TestCandidates(t *testing.T) {
	shared := map[string]struct{}{"seed.example.com": {}}
	c := &candidates{target: "example.com", entries: []string{"www", "mail"}, seeds: shared}
	if n := c.add(nil); n != 0 || len(c.seeds) != 1 {
		t.Fatalf("no names: added %d, seeds %v", n, c.seeds)
	}
	if n := c.add([]string{"api", "www", "bad name!"}); n != 1 {
		t.Errorf("first source added %d, want 1 (api)", n)
	}
	if n := c.add([]string{"api", "old", "OLD"}); n != 1 {
		t.Errorf("second source added %d, want 1 (old)", n)
	}
	if want := []string{"www", "mail", "api", "old"}; !slices.Equal(c.entries, want) {
		t.Errorf("entries = %v, want %v", c.entries, want)
	}
	if _, ok := c.seeds["old.example.com"]; !ok || len(shared) != 1 {
		t.Errorf("seeds = %v (shared %v): want the names added to a copy only", c.seeds, shared)
	}
}

// TestE2ELabRefusesSources: passive sources reach external services, so lab
// mode refuses them, and simulation ignores them with a note.
func TestE2ELabRefusesSources(t *testing.T) {
	zone := filepath.Join("examples", "labs", "lab1-first-scan.zone")
	if code, out := runCLIMerged(t, "-sources", "wayback", "-simulate-zone", zone, "lab.example"); code != exitUsage || !strings.Contains(out, "-sources") {
		t.Errorf("lab: exit %d\n%s", code, out)
	}
	wl := writeFile(t, "wl.txt", "www\n")
	if code, out := runCLIMerged(t, "-sources", "wayback", "-simulate", "-seed", "1", "-progress=false", "-w", wl, "example.com"); code != 0 || !strings.Contains(out, "-sources is ignored in simulation mode") {
		t.Errorf("simulate: exit %d\n%s", code, out)
	}
}

// TestE2ESimulateSkipsCT covers #150: simulation mode sends nothing off the
// machine, so -ct is ignored with a note instead of querying crt.sh.
func TestE2ESimulateSkipsCT(t *testing.T) {
	hit := false
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ct.Close()
	ctBaseURL = ct.URL + "/"
	t.Cleanup(func() { ctBaseURL = "" })

	wl := writeFile(t, "wl.txt", "www\nmail\n")
	code, out := runCLIMerged(t, "-ct", "-simulate", "-seed", "1", "-progress=false", "-w", wl, "example.com")
	if code != 0 || !strings.Contains(out, "-ct is ignored in simulation mode") {
		t.Errorf("exit %d, want 0 and a note that -ct is ignored\n%s", code, out)
	}
	if hit {
		t.Error("-simulate -ct contacted the CT server")
	}
}

// TestE2ELabRefusesCT: -ct reaches crt.sh, so lab mode refuses it.
func TestE2ELabRefusesCT(t *testing.T) {
	zone := filepath.Join("examples", "labs", "lab1-first-scan.zone")
	if code, out := runCLIMerged(t, "-ct", "-simulate-zone", zone, "lab.example"); code != exitUsage || !strings.Contains(out, "-ct") {
		t.Errorf("exit %d\n%s", code, out)
	}
}
