package tui

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/TMHSDigital/subenum/examples/labs"
	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"github.com/TMHSDigital/subenum/internal/labzone"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// zoneServer serves Lab 8's zone, signed with plain NSEC and allowing
// transfers, from a local server whose name server ns1 resolves to the
// server itself, so the transfer and the walk stay on the machine. It
// returns the server's address and port.
func zoneServer(t *testing.T) (addr, port string) {
	t.Helper()
	b, err := labs.Files.ReadFile("lab8-nsec-walk.zone")
	if err != nil {
		t.Fatal(err)
	}
	text := "$TRANSFER allow\n" + strings.Replace(string(b), "192.0.2.53", "127.0.0.1", 1)
	zone, err := labzone.Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := dnsserver.Listen(dnsserver.Options{}, zone.Handler([]string{"lab.example"}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	_, port, err = net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	return srv.Addr, port
}

// TestZoneTransferWalkAndStatsScan covers #418 end to end: with Zone
// Transfer and NSEC Walk on, the TUI asks the zone's name servers before the
// scan, scans the names they give with the wordlist's, says what each gave
// on the scan screen, and writes the run-quality report to the Stats File
// with the zone fields the CLI's -stats file has.
func TestZoneTransferWalkAndStatsScan(t *testing.T) {
	redirectConfig(t)
	addr, port := zoneServer(t)
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wl, []byte("www\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.jsonl")
	stats := filepath.Join(dir, "run.json")

	m := New(Options{Version: "test", TransferPort: port})
	sized, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 60})
	m = sized.(Model)
	for f, v := range map[int]string{
		fieldDomain: "lab.example", fieldWordlist: wl, fieldDNSServer: addr,
		fieldTypes: "A", fieldOutput: out, fieldFormat: "jsonl", fieldStats: stats,
	} {
		m.form.inputs[f].SetValue(v)
	}
	m.form.toggles[fieldAXFR] = true
	m.form.toggles[fieldNSECWalk] = true

	next, load := m.Update(keyCtrlR)
	m = next.(Model)
	if m.form.err != "" || load == nil {
		t.Fatalf("ctrl+r: error %q, load started %v", m.form.err, load != nil)
	}
	if !strings.Contains(m.form.View(), "asking the zone's name servers") {
		t.Error("the form does not say the zone's name servers are being asked")
	}
	next, listen := m.Update(load())
	m = drive(t, next.(Model), listen)

	sv := m.scanView
	if !sv.done || sv.failed() || sv.outputErr || sv.found != 6 {
		t.Fatalf("done %v, failed %v, output error %v, found %d; want a finished scan with 6 names\n%s",
			sv.done, sv.failed(), sv.outputErr, sv.found, strings.Join(sv.messages, "\n"))
	}
	notices := strings.Join(sv.messages, "\n")
	for _, want := range []string{
		"allowed AXFR of lab.example",
		"Zone transfer: 6 names under lab.example, 5 of them new candidates",
		"NSEC walk: 6 names under lab.example, 0 of them new candidates",
		"Wrote the run-quality report to " + stats,
	} {
		if !strings.Contains(notices, want) {
			t.Errorf("scan notices lack %q:\n%s", want, notices)
		}
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	got := map[string][]string{}
	for _, line := range lines[:len(lines)-1] {
		var r output.Result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("result line %q: %v", line, err)
		}
		got[r.Subdomain] = r.Sources
	}
	if want := []string{"wordlist", "axfr", "nsec"}; !reflect.DeepEqual(got["www.lab.example"], want) {
		t.Errorf("www sources = %v, want %v (all results: %v)", got["www.lab.example"], want, got)
	}
	if want := []string{"axfr", "nsec"}; !reflect.DeepEqual(got["payroll-archive.lab.example"], want) {
		t.Errorf("payroll-archive sources = %v, want %v", got["payroll-archive.lab.example"], want)
	}

	b, err := os.ReadFile(stats)
	if err != nil {
		t.Fatalf("no stats file: %v", err)
	}
	var s output.Summary
	if err := json.Unmarshal(b, &s); err != nil || len(s.Targets) != 1 {
		t.Fatalf("stats file (err %v): %s", err, b)
	}
	tg := s.Targets[0]
	if len(tg.AXFRAllowed) != 1 || tg.AXFRNames != 6 || tg.AXFRFound != 6 || tg.NSECNames != 6 || tg.NSECFound != 6 || tg.ZoneDenial != "nsec" {
		t.Errorf("stats zone fields: allowed %v, axfr_names %d, axfr_found %d, nsec_names %d, nsec_found %d, zone_denial %q",
			tg.AXFRAllowed, tg.AXFRNames, tg.AXFRFound, tg.NSECNames, tg.NSECFound, tg.ZoneDenial)
	}
	if tg.Processed != 6 || tg.Found != 6 || tg.Verdict == "" || tg.QueriesSent <= tg.Processed {
		t.Errorf("stats: processed %d, found %d, verdict %q, queries_sent %d", tg.Processed, tg.Found, tg.Verdict, tg.QueriesSent)
	}
}

// TestZoneFieldsSavedAndIgnoredInSimulation covers #418: the Zone Transfer,
// NSEC Walk and Stats File fields are remembered for the next session, and
// in simulation mode the name servers are not asked and the scan screen
// says so, while the Stats File is still written.
func TestZoneFieldsSavedAndIgnoredInSimulation(t *testing.T) {
	redirectConfig(t)
	dir := t.TempDir()
	stats := filepath.Join(dir, "run.json")
	f := newFormModel(savedConfig{})
	f.inputs[fieldDomain].SetValue("example.com")
	f.inputs[fieldStats].SetValue(" " + stats + " ")
	f.toggles[fieldAXFR], f.toggles[fieldNSECWalk] = true, true
	vals, errStr := f.validate()
	if errStr != "" {
		t.Fatalf("validate: %s", errStr)
	}
	if !vals.axfr || !vals.nsecWalk || vals.statsFile != stats {
		t.Errorf("axfr %v, nsec walk %v, stats file %q", vals.axfr, vals.nsecWalk, vals.statsFile)
	}
	if err := saveConfig(vals.saved); err != nil {
		t.Fatal(err)
	}
	saved, _ := loadSavedConfig()
	again := newFormModel(saved)
	if !again.toggles[fieldAXFR] || !again.toggles[fieldNSECWalk] || again.inputs[fieldStats].Value() != stats {
		t.Errorf("reloaded form: axfr %v, nsec walk %v, stats %q", again.toggles[fieldAXFR], again.toggles[fieldNSECWalk], again.inputs[fieldStats].Value())
	}

	// Simulation: no name server is asked, even one that does not exist.
	vals = formValues{
		Options: scan.Options{Config: scan.Config{
			Domain: "example.com", DNSServer: "192.0.2.1:53", Concurrency: 4, Timeout: time.Second, Attempts: 1,
			HitRate: 100, Types: []string{"A"}, Depth: 1, Simulate: true,
		}},
		axfr: true, nsecWalk: true, statsFile: stats,
		wordlist: filepath.Join(dir, "wl.txt"),
	}
	if err := os.WriteFile(vals.wordlist, []byte("www\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded := loadWordlistCmd(vals, Options{})().(wordlistLoadedMsg)
	if loaded.zone != nil || len(loaded.entries) != 1 {
		t.Fatalf("simulation: zone %+v, %d entries; want no zone lookup", loaded.zone, len(loaded.entries))
	}
	next, listen := Model{state: stateForm, form: newFormModel(savedConfig{})}.Update(loaded)
	m := drive(t, next.(Model), listen)
	if !strings.Contains(strings.Join(m.scanView.messages, "\n"), "Zone Transfer and NSEC Walk are ignored in simulation mode") {
		t.Errorf("no note that the zone fields were ignored:\n%s", strings.Join(m.scanView.messages, "\n"))
	}
	var s output.Summary
	if b, err := os.ReadFile(stats); err != nil || json.Unmarshal(b, &s) != nil || len(s.Targets) != 1 || !s.Simulated {
		t.Errorf("stats file after a simulated scan (err %v): %+v", err, s)
	}
}

// TestStatsFileWriteFailure covers #418: a Stats File that cannot be written
// is an error on the scan screen and fails the run, as -stats does.
func TestStatsFileWriteFailure(t *testing.T) {
	m := Model{scanView: newScanViewModel(120, 40, false), vals: formValues{
		Options:   scan.Options{Config: scan.Config{Domain: "example.com"}},
		statsFile: filepath.Join(t.TempDir(), "missing-dir", "run.json"),
	}}
	m.writeStats(m.summary(scan.Event{Kind: scan.EventDone}))
	if !m.scanView.outputErr || exitCode(m) != 1 || !strings.Contains(strings.Join(m.scanView.messages, "\n"), "cannot write the stats file") {
		t.Errorf("output error %v, exit %d, notices %q", m.scanView.outputErr, exitCode(m), m.scanView.messages)
	}
}

// TestLaunchWarningsOnForm covers #418: warnings about flags -tui ignores
// are shown on the form, which covers what was printed to stderr.
func TestLaunchWarningsOnForm(t *testing.T) {
	redirectConfig(t)
	m := New(Options{Warnings: []string{"-tui has no form field for -sarif; ignored"}})
	if view := m.form.View(); !strings.Contains(view, "⚠ -tui has no form field for -sarif; ignored") {
		t.Errorf("form lacks the launch warning:\n%s", view)
	}
	if view := New(Options{}).form.View(); strings.Contains(view, "⚠") {
		t.Errorf("form without warnings shows one:\n%s", view)
	}
}
