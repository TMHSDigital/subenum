package cli

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/examples/labs"
)

// lab8 reads the built-in Lab 8 scenario, so a test can change a copy.
func lab8(t *testing.T) string {
	t.Helper()
	b, err := labs.Files.ReadFile("lab8-nsec-walk.zone")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestE2ELabNSECWalk covers #437: against a lab zone signed with plain
// NSEC, -nsec-walk lists every name in it, each still looked up and tagged
// with source nsec, and the report counts them; it asks for no zone
// transfer without -axfr.
func TestE2ELabNSECWalk(t *testing.T) {
	t.Parallel()
	zone := writeFile(t, "lab8.zone", "$TRANSFER allow\n"+lab8(t))
	stats := filepath.Join(t.TempDir(), "run.json")
	code, out := runCLIMerged(t, "-nsec-walk", "-simulate-zone", zone, "-w", writeFile(t, "w.txt", "www\n"), "-format", "jsonl", "-stats", stats, "-progress=false", "lab.example")
	got := seenResults(t, lastJSONLines(out))
	want := map[string][]string{
		"www.lab.example":             {"wordlist", "nsec"},
		"mail.lab.example":            {"nsec"},
		"vpn.lab.example":             {"nsec"},
		"ns1.lab.example":             {"nsec"},
		"payroll-archive.lab.example": {"nsec"},
		"qa.build-farm.lab.example":   {"nsec"},
	}
	if code != exitOK || len(got) != len(want) {
		t.Fatalf("exit %d, results %v\n%s", code, got, out)
	}
	for name, sources := range want {
		if !slices.Equal(got[name].Sources, sources) {
			t.Errorf("%s: sources %v, want %v", name, got[name].Sources, sources)
		}
	}
	if !strings.Contains(out, "NSEC walk: listed 6 names of lab.example") || strings.Contains(out, "allowed AXFR") {
		t.Errorf("want the walk reported and no transfer asked for without -axfr:\n%s", out)
	}
	if tg := axfrSummary(t, stats).Targets[0]; tg.NSECNames != 6 || tg.NSECFound != 6 || tg.NSECStop != "" || tg.ZoneDenial != "nsec" {
		t.Errorf("report nsec_names = %d, nsec_found = %d, nsec_stop = %q, zone_denial = %q; want 6, 6, none and nsec", tg.NSECNames, tg.NSECFound, tg.NSECStop, tg.ZoneDenial)
	}

	// With -axfr too, both run, and a name both give lists both.
	code, out = runCLIMerged(t, "-axfr", "-nsec-walk", "-simulate-zone", zone, "-w", writeFile(t, "w2.txt", "www\n"), "-format", "jsonl", "-progress=false", "lab.example")
	if got := seenResults(t, lastJSONLines(out)); code != exitOK || !slices.Equal(got["mail.lab.example"].Sources, []string{"axfr", "nsec"}) {
		t.Errorf("-axfr -nsec-walk: exit %d, results %v\n%s", code, got, out)
	}
}

// TestE2ELabNSECWalkNotWalkable covers #437: against an NSEC3 or unsigned
// zone -nsec-walk does nothing beyond the probe and says why.
func TestE2ELabNSECWalkNotWalkable(t *testing.T) {
	t.Parallel()
	for denial, why := range map[string]string{
		"nsec3": "the zone is signed with NSEC3, which hides its names",
		"none":  "the zone is not signed with DNSSEC",
	} {
		zone := writeFile(t, denial+".zone", strings.Replace(lab8(t), "$DNSSEC nsec", "$DNSSEC "+denial, 1))
		stats := filepath.Join(t.TempDir(), "run.json")
		code, out := runCLIMerged(t, "-nsec-walk", "-simulate-zone", zone, "-w", writeFile(t, "w.txt", "www\n"), "-format", "jsonl", "-stats", stats, "-progress=false", "lab.example")
		if code != exitOK || !strings.Contains(out, "-nsec-walk: not walking lab.example: "+why) || strings.Contains(out, "payroll-archive") {
			t.Errorf("%s: exit %d\n%s", denial, code, out)
		}
		if tg := axfrSummary(t, stats).Targets[0]; tg.NSECNames != 0 || !strings.HasPrefix(tg.NSECStop, why) || tg.ZoneDenial != denial {
			t.Errorf("%s: report nsec_names = %d, nsec_stop = %q, zone_denial = %q", denial, tg.NSECNames, tg.NSECStop, tg.ZoneDenial)
		}
	}
	wl := writeFile(t, "wl.txt", "www\n")
	if code, out := runCLIMerged(t, "-nsec-walk", "-simulate", "-seed", "1", "-progress=false", "-w", wl, "example.com"); code != 0 || !strings.Contains(out, "-nsec-walk is ignored in simulation mode") {
		t.Errorf("simulate: exit %d\n%s", code, out)
	}
}

// TestE2ELabNSECWalkBounds covers #437: -max-queries stops the walk, which
// keeps what it listed and says why, and -exclude keeps out-of-scope names
// out of the candidates.
func TestE2ELabNSECWalkBounds(t *testing.T) {
	t.Parallel()
	wl := writeFile(t, "w.txt", "www\n")
	stats := filepath.Join(t.TempDir(), "run.json")
	code, out := runCLIMerged(t, "-nsec-walk", "-simulate-zone", "lab8", "-w", wl, "-max-queries", "3", "-stats", stats, "-progress=false", "lab.example")
	if code != exitOK || !strings.Contains(out, "stopped after 3 queries (it reached its limit of 3 queries); using the 3 names listed") {
		t.Errorf("-max-queries 3: exit %d\n%s", code, out)
	}
	if tg := axfrSummary(t, stats).Targets[0]; tg.NSECNames != 3 || !strings.Contains(tg.NSECStop, "limit of 3 queries") {
		t.Errorf("-max-queries 3: report nsec_names = %d, nsec_stop = %q", tg.NSECNames, tg.NSECStop)
	}

	code, out = runCLIMerged(t, "-nsec-walk", "-simulate-zone", "lab8", "-w", wl, "-exclude", "*.build-farm.lab.example,payroll-archive.lab.example", "-format", "jsonl", "-progress=false", "lab.example")
	got := seenResults(t, lastJSONLines(out))
	if _, ok := got["mail.lab.example"]; code != exitOK || !ok || strings.Contains(out, "payroll-archive") || strings.Contains(out, "qa.build-farm") {
		t.Errorf("-exclude: exit %d, results %v\n%s", code, got, out)
	}
}
