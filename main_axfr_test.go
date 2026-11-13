package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/output"
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
	_, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	old := axfrPort
	axfrPort = port
	t.Cleanup(func() { axfrPort = old })
	return srv
}

// TestE2EZoneTransfer covers #85: a name server that allows AXFR gives
// names the wordlist lacks, each still verified by resolution (gone. is in
// the zone but does not resolve), and the report names the server.
func TestE2EZoneTransfer(t *testing.T) {
	srv := axfrZone(t, true, "")
	wl := writeFile(t, "wl.txt", "www\nmail\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	code, out := runCLIMerged(t, "-axfr", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl, "example.test")
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
}

// TestE2EZoneTransferRefused: a refusal, the correct configuration, is not
// an error and leaves the scan to the wordlist.
func TestE2EZoneTransferRefused(t *testing.T) {
	srv := axfrZone(t, false, "nsec3")
	wl := writeFile(t, "wl.txt", "www\nmail\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	code, out := runCLIMerged(t, "-axfr", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl, "example.test")
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
	srv := axfrZone(t, false, "nsec")
	wl := writeFile(t, "wl.txt", "www\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	code, out := runCLIMerged(t, "-axfr", "-dns-server", srv.Addr, "-type", "A", "-progress=false", "-stats", stats, "-w", wl, "example.test")
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

// TestE2ELabRefusesAXFR: a transfer would go to the zone's real name
// servers, so lab mode refuses -axfr; simulation ignores it with a note.
func TestE2ELabRefusesAXFR(t *testing.T) {
	zone := filepath.Join("examples", "labs", "lab1-first-scan.zone")
	if code, out := runCLIMerged(t, "-axfr", "-simulate-zone", zone, "lab.example"); code != exitUsage || !strings.Contains(out, "-axfr") {
		t.Errorf("lab: exit %d\n%s", code, out)
	}
	wl := writeFile(t, "wl.txt", "www\n")
	if code, out := runCLIMerged(t, "-axfr", "-simulate", "-seed", "1", "-progress=false", "-w", wl, "example.com"); code != 0 || !strings.Contains(out, "-axfr is ignored in simulation mode") {
		t.Errorf("simulate: exit %d\n%s", code, out)
	}
}
