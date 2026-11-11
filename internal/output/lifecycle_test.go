package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// Package-level tests for the results file, SARIF, summary and diff/quiet
// writers (#171), which were reached only by the CLI's end-to-end tests.

// noTempFiles fails if dir holds a leftover temporary results file.
func noTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestFileCommitReplacesTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.txt")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := CreateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("new\n"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "old\n" {
		t.Fatalf("target changed before Close: %q", got)
	}
	if err := f.Close(true); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "new\n" {
		t.Fatalf("target after commit = %q", got)
	}
	if err := f.Close(true); err != nil {
		t.Fatalf("second Close = %v, want a no-op", err)
	}
	noTempFiles(t, dir)
}

func TestFileDiscardKeepsTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.txt")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := CreateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("partial\n")
	if err := f.Close(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "old\n" {
		t.Fatalf("discarded run changed the target: %q", got)
	}
	noTempFiles(t, dir)

	// A new path that is never committed is never created.
	fresh := filepath.Join(dir, "fresh.txt")
	f, err = CreateFile(fresh)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close(false)
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatalf("uncommitted new file exists: %v", err)
	}
	noTempFiles(t, dir)
}

func TestCreateFileMissingDirectory(t *testing.T) {
	if _, err := CreateFile(filepath.Join(t.TempDir(), "missing", "results.txt")); err == nil {
		t.Fatal("CreateFile in a missing directory succeeded")
	}
}

func TestCreateFileWritesNonRegularTargetDirectly(t *testing.T) {
	fi, err := os.Stat(os.DevNull)
	if err != nil || fi.Mode().IsRegular() {
		t.Skipf("%s is not a device here", os.DevNull)
	}
	f, err := CreateFile(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if f.tmp {
		t.Fatal("a device target got a temporary file")
	}
	_, _ = f.WriteString("discarded\n")
	if err := f.Close(true); err != nil {
		t.Fatal(err)
	}
}

func readSARIF(t *testing.T, path string) (sarifLog, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc sarifLog
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	return doc, data
}

func TestWriteSARIFNoResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	results := []Result{{Result: scan.Result{Subdomain: "www.example.com", Records: []dns.Record{{Type: "A", Value: "192.0.2.1"}}}}}
	if err := WriteSARIF(path, "v1.2.3", results); err != nil {
		t.Fatal(err)
	}
	doc, data := readSARIF(t, path)
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "subenum" || doc.Runs[0].Tool.Driver.Version != "v1.2.3" {
		t.Fatalf("document header = %+v", doc)
	}
	// Code scanning rejects null arrays: both must be present and empty.
	for _, want := range []string{`"results": []`, `"rules": []`} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("SARIF lacks %s:\n%s", want, data)
		}
	}
}

func TestWriteSARIFTakeovers(t *testing.T) {
	cname := []dns.Record{{Type: "CNAME", Value: "gone.herokuapp.com."}}
	results := []Result{
		{Result: scan.Result{Subdomain: "a.example.com", Records: cname, Takeover: "dangling:heroku"}},
		{Result: scan.Result{Subdomain: "a.example.com", Records: cname, Takeover: "provider:heroku"}},
		{Result: scan.Result{Subdomain: "b.example.com", Takeover: "dangling"}},
		{Result: scan.Result{Subdomain: "c.example.com", Records: cname, Takeover: "dangling:heroku"}},
		{Result: scan.Result{Subdomain: "www.example.com"}},
		{Result: scan.Result{Subdomain: "sub.example.com", Records: []dns.Record{{Type: "NS", Value: "ns1.gone.example"}}, Takeover: "dangling-ns"}},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "out.sarif")
	if err := WriteSARIF(path, "v1", results); err != nil {
		t.Fatal(err)
	}
	doc, first := readSARIF(t, path)
	run := doc.Runs[0]
	if len(run.Results) != 5 {
		t.Fatalf("%d results, want the 5 takeover candidates", len(run.Results))
	}
	if msg := run.Results[4].Message.Text; run.Results[4].RuleID != "subenum/dangling-ns" || !strings.Contains(msg, "sub.example.com is delegated to ns1.gone.example") || run.Results[4].Level != "error" {
		t.Errorf("dangling-ns result = %+v", run.Results[4])
	}
	var ruleIDs []string
	for _, r := range run.Tool.Driver.Rules {
		ruleIDs = append(ruleIDs, r.ID)
	}
	wantRules := []string{"subenum/dangling-cname", "subenum/dangling-cname/heroku", "subenum/dangling-ns", "subenum/takeover-prone-provider/heroku"}
	if strings.Join(ruleIDs, ",") != strings.Join(wantRules, ",") {
		t.Fatalf("rules = %v, want each once, sorted: %v", ruleIDs, wantRules)
	}

	levels := map[string]string{}
	fingerprints := map[string]bool{}
	for _, r := range run.Results {
		levels[r.RuleID] = r.Level
		fp := r.PartialFingerprints["subenumTakeover/v1"]
		if fp == "" || fingerprints[fp] {
			t.Errorf("fingerprint %q missing or repeated", fp)
		}
		fingerprints[fp] = true
		if r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result without a location: %+v", r)
		}
	}
	if levels["subenum/dangling-cname/heroku"] != "error" || levels["subenum/dangling-cname"] != "error" || levels["subenum/takeover-prone-provider/heroku"] != "note" {
		t.Fatalf("levels = %v", levels)
	}
	if msg := run.Results[0].Message.Text; !strings.Contains(msg, "a.example.com is a CNAME for gone.herokuapp.com") {
		t.Fatalf("message = %q, want the CNAME target named", msg)
	}

	// The same input writes the same bytes, so fingerprints are stable
	// across runs.
	again := filepath.Join(dir, "again.sarif")
	if err := WriteSARIF(again, "v1", results); err != nil {
		t.Fatal(err)
	}
	if _, second := readSARIF(t, again); !bytes.Equal(first, second) {
		t.Fatal("SARIF output is not deterministic")
	}
}

func TestWriteSARIFUnwritablePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "out.sarif")
	if err := WriteSARIF(path, "v1", []Result{{Result: scan.Result{Subdomain: "a.example.com", Takeover: "dangling"}}}); err == nil {
		t.Fatal("WriteSARIF to a missing directory succeeded")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("partial file exists: %v", err)
	}
}

func TestWriteSummaryFile(t *testing.T) {
	dir := t.TempDir()
	for _, verdict := range []string{"complete", "degraded", "unreliable", "interrupted", "failed"} {
		path := filepath.Join(dir, verdict+".json")
		in := Summary{Type: "summary", Schema: SummarySchema, Verdict: verdict, Reason: "test",
			Targets: []TargetSummary{{Domain: "example.com", Status: "ok", Verdict: verdict}}}
		if err := WriteSummaryFile(path, in); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var out Summary
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("%s: invalid JSON: %v", verdict, err)
		}
		if out.Verdict != verdict || len(out.Targets) != 1 || out.Targets[0].Processed != 0 {
			t.Fatalf("%s: round trip = %+v", verdict, out)
		}
	}
	noTempFiles(t, dir)
	if err := WriteSummaryFile(filepath.Join(dir, "missing", "s.json"), Summary{}); err == nil {
		t.Fatal("WriteSummaryFile to a missing directory succeeded")
	}
}

func TestSummaryLineOnlyInJSONL(t *testing.T) {
	for _, format := range []Format{FormatText, FormatJSON, FormatCSV, FormatJSONL} {
		var stdout, file bytes.Buffer
		bw := bufio.NewWriter(&file)
		w := New(bw, false, format)
		w.SetStdout(&stdout)
		w.Summary(Summary{Type: "summary", Verdict: "complete"})
		_ = bw.Flush()
		has := strings.Contains(stdout.String(), `"verdict":"complete"`) && strings.Contains(file.String(), `"verdict":"complete"`)
		if has != (format == FormatJSONL) {
			t.Errorf("format %v: summary on stdout/file = %v, want %v", format, has, format == FormatJSONL)
		}
	}
}

func TestDiffOutput(t *testing.T) {
	results := []Result{
		{Result: scan.Result{Subdomain: "new.example.com", Records: []dns.Record{{Type: "A", Value: "192.0.2.1"}}}, Change: "added"},
		{Result: scan.Result{Subdomain: "old.example.com"}, Change: "removed"},
		{Result: scan.Result{Subdomain: "moved.example.com", Records: []dns.Record{{Type: "A", Value: "192.0.2.3"}}}, Change: "changed"},
	}
	emit := func(format Format) string {
		var stdout bytes.Buffer
		w := New(nil, false, format)
		w.SetStdout(&stdout)
		w.SetPlain(true)
		w.SetDiff(true)
		for _, r := range results {
			w.Emit(r)
		}
		if err := w.Finish(); err != nil {
			t.Fatal(err)
		}
		return stdout.String()
	}

	if got, want := emit(FormatText), "+ new.example.com\n- old.example.com\n~ moved.example.com\n"; got != want {
		t.Errorf("text diff = %q, want %q", got, want)
	}
	csvOut := emit(FormatCSV)
	if !strings.HasPrefix(csvOut, "subdomain,type,value,change\n") || !strings.Contains(csvOut, "new.example.com,A,192.0.2.1,added") ||
		!strings.Contains(csvOut, "old.example.com,,,removed") || !strings.Contains(csvOut, "moved.example.com,A,192.0.2.3,changed") {
		t.Errorf("csv diff =\n%s", csvOut)
	}
	jsonl := emit(FormatJSONL)
	for _, want := range []string{`"change":"added"`, `"change":"removed"`, `"change":"changed"`} {
		if !strings.Contains(jsonl, want) {
			t.Errorf("jsonl diff lacks %s:\n%s", want, jsonl)
		}
	}
}

func TestQuietKeepsNoticesAndErrors(t *testing.T) {
	var stderr bytes.Buffer
	w := New(nil, false, FormatText)
	w.SetStderr(&stderr)
	w.SetQuiet(true)
	w.Info("info line")
	w.Notice("notice line")
	w.Error("bad %s", "thing")
	got := stderr.String()
	if strings.Contains(got, "info line") {
		t.Errorf("Info printed under SetQuiet: %q", got)
	}
	if !strings.Contains(got, "notice line\n") || !strings.Contains(got, "Error: bad thing\n") {
		t.Errorf("stderr = %q, want the notice and the error", got)
	}

	stderr.Reset()
	w.SetQuiet(false)
	w.Info("info line")
	if stderr.String() != "info line\n" {
		t.Errorf("Info without quiet = %q", stderr.String())
	}
}
