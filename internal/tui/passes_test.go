package tui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// drive runs cmd, and every command the messages it produces lead to,
// through the model until none is left: the scan has ended.
func drive(t *testing.T, m Model, cmd tea.Cmd) Model {
	t.Helper()
	queue := []tea.Cmd{cmd}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		switch msg := c().(type) {
		case nil:
		case tea.BatchMsg:
			queue = append(queue, msg...)
		default:
			next, nc := m.Update(msg)
			m = next.(Model)
			queue = append(queue, nc)
		}
	}
	return m
}

// sourceServers starts a crt.sh and a Wayback Machine stand-in and returns
// their endpoints by source name, and the number of requests they got.
func sourceServers(t *testing.T) (map[string]string, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	serve := func(body string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	return map[string]string{
		"ct":      serve(`[{"name_value": "legacy-billing.example.com"}]`) + "/",
		"wayback": serve("http://old-shop.example.com/cart\nhttps://www.example.com/\n"),
	}, &hits
}

// TestSourcesAndPermuteFields covers #274: the Sources field takes what
// -sources does, an unknown source is rejected on the form, and both fields
// are saved for the next session.
func TestSourcesAndPermuteFields(t *testing.T) {
	redirectConfig(t)
	m := newFormModel(savedConfig{})
	m.inputs[fieldDomain].SetValue("example.com")
	m.inputs[fieldSources].SetValue(" Wayback, ct ")
	m.toggles[fieldPermute] = true
	vals, errStr := m.validate()
	if errStr != "" {
		t.Fatalf("validate: %s", errStr)
	}
	if !reflect.DeepEqual(vals.sources, []string{"ct", "wayback"}) || !vals.permute {
		t.Errorf("sources %q, permute %v; want ct and wayback in their running order, and permute on", vals.sources, vals.permute)
	}
	if err := saveConfig(vals.saved); err != nil {
		t.Fatal(err)
	}
	saved, _ := loadSavedConfig()
	again := newFormModel(saved)
	if got := again.inputs[fieldSources].Value(); got != "ct,wayback" || !again.toggles[fieldPermute] {
		t.Errorf("reloaded form: sources %q, permute %v", got, again.toggles[fieldPermute])
	}

	m.inputs[fieldSources].SetValue("ct,shodan")
	if _, errStr := m.validate(); !strings.HasPrefix(errStr, `Sources: unknown source "shodan"`) {
		t.Errorf("unknown source: got %q", errStr)
	}
	m.inputs[fieldSources].SetValue("")
	if vals, errStr := m.validate(); errStr != "" || len(vals.sources) != 0 {
		t.Errorf("blank sources: %q, %q; want no error and no sources", errStr, vals.sources)
	}
}

// TestSourcesAndPermutationScan covers #274 end to end: with Sources and
// Permute set, the TUI asks the sources before the scan, scans their names
// with the wordlist's, runs the permutation pass after it, and writes what
// proposed each result and the report the CLI writes.
func TestSourcesAndPermutationScan(t *testing.T) {
	redirectConfig(t)
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "www.example.com", "legacy-billing.example.com", "old-shop.example.com", "www-dev.example.com":
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"192.0.2.10"}}
			}
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	urls, _ := sourceServers(t)
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wl, []byte("www\nmail\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.jsonl")

	m := New(Options{Version: "test", SourceURLs: urls})
	sized, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = sized.(Model)
	for f, v := range map[int]string{
		fieldDomain: "example.com", fieldWordlist: wl, fieldSources: "ct,wayback", fieldDNSServer: srv.Addr,
		fieldTypes: "A", fieldOutput: out, fieldFormat: "jsonl",
	} {
		m.form.inputs[f].SetValue(v)
	}
	m.form.toggles[fieldPermute] = true

	next, load := m.Update(keyCtrlR)
	m = next.(Model)
	if m.form.err != "" || load == nil {
		t.Fatalf("ctrl+r: error %q, load started %v", m.form.err, load != nil)
	}
	if !strings.Contains(m.form.View(), "asking the passive sources") {
		t.Error("the form does not say the sources are being asked")
	}
	next, listen := m.Update(load())
	m = drive(t, next.(Model), listen)

	sv := m.scanView
	if !sv.done || sv.failed() || sv.found != 4 {
		t.Fatalf("done %v, failed %v, found %d; want a finished scan with 4 names\n%s", sv.done, sv.failed(), sv.found, sv.View())
	}
	notices := strings.Join(sv.messages, "\n")
	for _, want := range []string{
		"Certificate Transparency: 1 names under example.com, 1 of them new candidates",
		"Wayback Machine: 2 names under example.com, 1 of them new candidates",
		"Permutation pass: ",
	} {
		if !strings.Contains(notices, want) {
			t.Errorf("scan notices lack %q:\n%s", want, notices)
		}
	}
	if view := sv.View(); !strings.Contains(view, "Verdict: ") || !strings.Contains(view, "found 4") {
		t.Errorf("finished screen:\n%s", view)
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
		if r.Permutation != (r.Subdomain == "www-dev.example.com") {
			t.Errorf("%s: permutation = %v", r.Subdomain, r.Permutation)
		}
		got[r.Subdomain] = r.Sources
	}
	want := map[string][]string{
		"www.example.com":            {"wordlist", "wayback"},
		"legacy-billing.example.com": {"ct"},
		"old-shop.example.com":       {"wayback"},
		"www-dev.example.com":        {"permute"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("result sources:\n got %v\nwant %v", got, want)
	}

	var s output.Summary
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &s); err != nil || len(s.Targets) != 1 {
		t.Fatalf("summary line (err %v): %s", err, lines[len(lines)-1])
	}
	tg := s.Targets[0]
	wantSources := []output.SourceSummary{{Name: "ct", Names: 1, Found: 1}, {Name: "wayback", Names: 2, Found: 2}}
	if !reflect.DeepEqual(tg.Sources, wantSources) || tg.CTNames != 1 {
		t.Errorf("report sources = %+v, ct_names %d; want %+v", tg.Sources, tg.CTNames, wantSources)
	}
	p := tg.Permutation
	if p == nil || p.Seeds != 3 || p.Found != 1 || p.Candidates == 0 || p.Processed != int64(p.Candidates) || p.Verdict == "" {
		t.Errorf("report permutation = %+v; want 3 seeds, 1 found and every candidate processed", p)
	}
	// The report's counts are the main pass's: the wordlist's two names and
	// the two new ones from the sources.
	if tg.Processed != 4 || tg.Found != 3 {
		t.Errorf("report: processed %d, found %d; want the main pass's 4 and 3", tg.Processed, tg.Found)
	}
}

// TestSourcesNotAskedInSimulation covers #274: simulation mode sends nothing
// off the machine, so the sources are not asked and the scan screen says so;
// the permutation pass still runs.
func TestSourcesNotAskedInSimulation(t *testing.T) {
	redirectConfig(t)
	urls, hits := sourceServers(t)
	vals := formValues{
		Options: scan.Options{Config: scan.Config{
			Domain: "example.com", DNSServer: "8.8.8.8:53", Concurrency: 4, Timeout: time.Second, Attempts: 1,
			HitRate: 100, Types: []string{"A"}, Depth: 1, Simulate: true,
		}},
		sources: []string{"ct", "wayback"}, permute: true,
		wordlist: filepath.Join(t.TempDir(), "wl.txt"),
	}
	if err := os.WriteFile(vals.wordlist, []byte("www\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded := loadWordlistCmd(vals, Options{SourceURLs: urls})().(wordlistLoadedMsg)
	if hits.Load() != 0 || len(loaded.lookups) != 0 || len(loaded.entries) != 1 {
		t.Fatalf("simulation: %d source requests, lookups %+v, %d entries; want no request", hits.Load(), loaded.lookups, len(loaded.entries))
	}
	next, listen := Model{state: stateForm, form: newFormModel(savedConfig{})}.Update(loaded)
	m := drive(t, next.(Model), listen)
	sv := m.scanView
	if !strings.Contains(strings.Join(sv.messages, "\n"), "passive sources are ignored in simulation mode") {
		t.Errorf("no note that the sources were ignored:\n%s", strings.Join(sv.messages, "\n"))
	}
	if !sv.done || sv.failed() || sv.perm == nil || !sv.perm.done || sv.perm.seeds != 1 {
		t.Errorf("done %v, failed %v, permutation %+v; want a finished permutation pass from one seed", sv.done, sv.failed(), sv.perm)
	}
	if want := int64(1 + sv.perm.candidates); sv.processed != want || sv.total != want {
		t.Errorf("finished counters %d/%d, want both passes' %d", sv.processed, sv.total, want)
	}
}

// TestFailedSourceDoesNotStopTheScan covers #274: a source that cannot be
// reached is a warning on the scan screen and an error in the report, and
// the scan runs with the wordlist's names.
func TestFailedSourceDoesNotStopTheScan(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer down.Close()
	lookups := fetchSources(t.Context(), "example.com", []string{"wayback"}, Options{SourceURLs: map[string]string{"wayback": down.URL}})
	if len(lookups) != 1 || lookups[0].fetched || lookups[0].err == "" {
		t.Fatalf("lookups = %+v, want one failed lookup", lookups)
	}
	cands := candidates.New("example.com", []string{"www"}, nil)
	if added := cands.Add(lookups[0].name, lookups[0].names); added != 0 || !reflect.DeepEqual(cands.Entries(), []string{"www"}) ||
		!reflect.DeepEqual(cands.SourcesOf("www.example.com"), candidates.FromWordlist) {
		t.Errorf("entries %q, sources of www %v; want the wordlist's names alone", cands.Entries(), cands.SourcesOf("www.example.com"))
	}

	m := Model{scanView: newScanViewModel(120, 40, false), lookups: lookups, vals: formValues{Options: scan.Options{Config: scan.Config{Domain: "example.com"}}}}
	if tg := m.summary(scan.Event{Kind: scan.EventDone}).Targets[0]; len(tg.Sources) != 1 || tg.Sources[0].Error == "" {
		t.Errorf("report sources = %+v, want the failed lookup's error", tg.Sources)
	}
}

// TestPermutationPassStates covers #274 on the scan screen: when the main
// pass leads to a permutation pass and when it does not, and how a pass that
// did not run to completion ends the scan.
func TestPermutationPassStates(t *testing.T) {
	mainDone := eventMsg{scan.Event{Kind: scan.EventDone, Processed: 5, Total: 5, Found: 1, Stats: scan.Stats{Found: 1, NXDomain: 4}}}
	start := func(setup func(*scanViewModel)) Model {
		sv := newScanViewModel(120, 40, false)
		sv.permute = true
		if setup != nil {
			setup(&sv)
		}
		return Model{state: stateScan, scanView: sv, vals: formValues{Options: scan.Options{Config: scan.Config{Domain: "example.com"}}, permute: true}, foundBy: map[string]int{}}
	}
	update := func(m Model, msgs ...tea.Msg) Model {
		for _, msg := range msgs {
			next, _ := m.updateScan(msg)
			m = next.(Model)
		}
		return m
	}

	// The main pass's end is not the scan's: the permutation pass follows.
	m := update(start(nil), mainDone)
	if m.scanView.done || m.scanView.main == nil || !strings.Contains(m.scanView.View(), "permutation pass") {
		t.Fatalf("after the main pass: done %v, want the permutation pass announced\n%s", m.scanView.done, m.scanView.View())
	}
	// Nothing was found, so there is nothing to permute and the scan ends.
	m = update(m, permutationReadyMsg{})
	if !m.scanView.done || m.scanView.perm != nil || m.scanView.failed() || !strings.Contains(m.scanView.View(), "Done - processed 5/5") {
		t.Errorf("nothing to permute: done %v, perm %+v\n%s", m.scanView.done, m.scanView.perm, m.scanView.View())
	}

	// A user abort or a reliability abort of the main pass ends the scan.
	if m := update(start(func(sv *scanViewModel) { sv.aborted = true }), mainDone); !m.scanView.done || m.scanView.main != nil {
		t.Error("an aborted main pass was followed by a permutation pass")
	}
	abortedDone := mainDone
	abortedDone.Failed, abortedDone.Stats.Aborted = true, true
	if m := update(start(nil), eventMsg{scan.Event{Kind: scan.EventError, Fatal: true, Message: "too many failures"}}, abortedDone); !m.scanView.done || !m.scanView.failed() {
		t.Error("a main pass the reliability guard aborted was followed by a permutation pass")
	}

	// ctrl+c while the candidates are built: the pass does not start, and
	// the scan ends as an interrupted one.
	m = update(start(nil), mainDone)
	m.scanView.aborted = true
	m = update(m, permutationReadyMsg{seeds: 1, candidates: []string{"www-dev"}})
	if !m.scanView.done || m.events != nil || !m.scanView.perm.unfinished() || !strings.Contains(m.scanView.View(), "Aborted - processed 5/5") {
		t.Errorf("abort before the permutation pass: done %v, perm %+v", m.scanView.done, m.scanView.perm)
	}
	// Without an interrupt, a pass that did not run degrades the verdict.
	var tg output.TargetSummary
	tg.Verdict = scan.VerdictComplete
	m.scanView.perm.summarize(&tg, false, "")
	if tg.Verdict != scan.VerdictDegraded || tg.Reason != "permutation pass: it did not run to completion" {
		t.Errorf("unfinished pass: verdict %q, reason %q", tg.Verdict, tg.Reason)
	}

	// A permutation pass that fails before its candidates fails the scan,
	// but the main pass's results are still written.
	path := filepath.Join(t.TempDir(), "out.json")
	f, err := output.CreateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m = update(start(nil), mainDone)
	m.out, m.outFile = output.NewFile(f.Writer, false, output.FormatJSON), f
	m.out.Emit(found("www.example.com", nil))
	m.scanView.perm = &permutationPass{seeds: 1, candidates: 90}
	m = update(m, eventMsg{scan.Event{Kind: scan.EventError, Fatal: true, Message: "resolver failed preflight"}}, eventMsg{scan.Event{Kind: scan.EventDone, Stopped: true, Failed: true}})
	if !m.scanView.done || !m.scanView.failed() || exitCode(m) != 1 || !strings.Contains(m.scanView.View(), "processed 5/5") {
		t.Errorf("failed permutation pass: done %v, failed %v\n%s", m.scanView.done, m.scanView.failed(), m.scanView.View())
	}
	if data, err := os.ReadFile(path); err != nil || !strings.Contains(string(data), "www.example.com") {
		t.Errorf("results file after a failed permutation pass (err %v): %q", err, data)
	}
}
