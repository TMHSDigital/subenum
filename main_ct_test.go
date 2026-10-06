package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// TestE2ELabRefusesCT: -ct reaches crt.sh, so lab mode refuses it.
func TestE2ELabRefusesCT(t *testing.T) {
	zone := filepath.Join("examples", "labs", "lab1-first-scan.zone")
	if code, out := runCLIMerged(t, "-ct", "-simulate-zone", zone, "lab.example"); code != exitUsage || !strings.Contains(out, "-ct") {
		t.Errorf("exit %d\n%s", code, out)
	}
}
