package output

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written. Used to assert on the streaming text output the Writer prints there.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = orig
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestWriterSimulateTextPrefix(t *testing.T) {
	w := New(nil, true, FormatText)
	out := captureStdout(t, func() {
		w.Result("www.example.com", []dns.Record{{Type: "A", Value: "1.2.3.4"}})
	})
	if !strings.Contains(out, "Found (SIMULATED): www.example.com") {
		t.Errorf("expected simulated prefix on stdout, got %q", out)
	}

	wLive := New(nil, false, FormatText)
	outLive := captureStdout(t, func() {
		wLive.Result("www.example.com", []dns.Record{{Type: "A", Value: "1.2.3.4"}})
	})
	if strings.Contains(outLive, "SIMULATED") {
		t.Errorf("live mode must not tag results as simulated, got %q", outLive)
	}
}

func TestNewFileWriterSkipsStdout(t *testing.T) {
	tmp, err := os.CreateTemp("", "output-fileonly-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	bw := bufio.NewWriter(tmp)
	w := NewFile(bw, false, FormatText)

	out := captureStdout(t, func() {
		w.Result("www.example.com", []dns.Record{{Type: "A", Value: "1.2.3.4"}})
		w.Finish()
	})
	if out != "" {
		t.Errorf("file-only writer must not write to stdout, got %q", out)
	}

	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "www.example.com") {
		t.Errorf("expected file to contain the result, got:\n%s", content)
	}
}

func TestWriterCSVEmptyRecords(t *testing.T) {
	tmp, err := os.CreateTemp("", "output-csv-empty-*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	bw := bufio.NewWriter(tmp)
	w := New(bw, false, FormatCSV)
	// A resolved domain with no records still gets one row with empty fields.
	// Finish must run inside the capture because csv.Writer buffers until flush.
	out := captureStdout(t, func() {
		w.Result("www.example.com", nil)
		w.Finish()
	})
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "www.example.com,,") {
		t.Errorf("expected empty-record fallback row in file, got:\n%s", content)
	}
	if !strings.Contains(out, "www.example.com,,") {
		t.Errorf("expected empty-record fallback row on stdout, got:\n%s", out)
	}
}

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"":     FormatText,
		"text": FormatText,
		"JSON": FormatJSON,
		"csv":  FormatCSV,
	}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil {
			t.Errorf("ParseFormat(%q) error: %v", in, err)
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestWriterResultText(t *testing.T) {
	tmp, err := os.CreateTemp("", "output-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	bw := bufio.NewWriter(tmp)
	w := New(bw, false, FormatText)

	domains := []string{"www.example.com", "api.example.com", "mail.example.com"}
	for _, d := range domains {
		w.Result(d, []dns.Record{{Type: "A", Value: "1.2.3.4"}})
	}
	w.Finish()
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range domains {
		if !strings.Contains(string(content), d) {
			t.Errorf("expected output file to contain %q\nGot:\n%s", d, content)
		}
	}
}

func TestWriterResultJSONFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "output-json-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	bw := bufio.NewWriter(tmp)
	w := New(bw, false, FormatJSON)
	w.Result("www.example.com", []dns.Record{{Type: "A", Value: "93.184.216.34"}})
	w.Result("ipv6.example.com", []dns.Record{{Type: "AAAA", Value: "2606:2800:220:1::1"}})
	w.Finish()
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}

	var results []Result
	if err := json.Unmarshal(content, &results); err != nil {
		t.Fatalf("output is not valid JSON array: %v\nGot:\n%s", err, content)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Subdomain != "www.example.com" || results[0].Records[0].Type != "A" {
		t.Errorf("unexpected first result: %+v", results[0])
	}
}

// TestWriterJSONFinishGatesOutput locks in the contract main.run relies on:
// structured output is emitted only by Finish, so skipping Finish on an error
// path produces no spurious empty JSON array.
func TestWriterJSONFinishGatesOutput(t *testing.T) {
	// Error path: results buffered (or none) but Finish never called.
	noFinish, err := os.CreateTemp("", "output-json-nofinish-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(noFinish.Name()) }()

	bw := bufio.NewWriter(noFinish)
	_ = New(bw, false, FormatJSON)
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := noFinish.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(noFinish.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 0 {
		t.Errorf("expected no structured output without Finish, got:\n%s", content)
	}

	// Success path: Finish with zero results emits an empty JSON array.
	withFinish, err := os.CreateTemp("", "output-json-finish-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(withFinish.Name()) }()

	bw2 := bufio.NewWriter(withFinish)
	w := New(bw2, false, FormatJSON)
	w.Finish()
	if err := bw2.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := withFinish.Close(); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(withFinish.Name())
	if err != nil {
		t.Fatal(err)
	}
	var results []Result
	if err := json.Unmarshal(content, &results); err != nil {
		t.Fatalf("Finish output is not a valid JSON array: %v\nGot:\n%s", err, content)
	}
	if len(results) != 0 {
		t.Errorf("expected empty array from Finish with no results, got %d", len(results))
	}
}

func TestWriterResultCSVFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "output-csv-*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	bw := bufio.NewWriter(tmp)
	w := New(bw, false, FormatCSV)
	w.Result("www.example.com", []dns.Record{
		{Type: "A", Value: "1.1.1.1"},
		{Type: "AAAA", Value: "2606::1"},
	})
	w.Finish()
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	got := string(content)
	if !strings.Contains(got, "subdomain,type,value") {
		t.Errorf("expected CSV header, got:\n%s", got)
	}
	if !strings.Contains(got, "www.example.com,A,1.1.1.1") {
		t.Errorf("expected A row, got:\n%s", got)
	}
	if !strings.Contains(got, "www.example.com,AAAA,2606::1") {
		t.Errorf("expected AAAA row, got:\n%s", got)
	}
}
