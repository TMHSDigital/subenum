package output

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
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
		if err := w.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
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
		if err := w.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
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
	if err := w.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
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
	if err := w.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
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
	if err := w.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
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
	if err := w.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
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

// TestWriterPlainAndRecords covers #34: piped text output is bare names, and
// -show-records appends TYPE=value pairs on stdout and in the file.
func TestWriterPlainAndRecords(t *testing.T) {
	recs := []dns.Record{{Type: "A", Value: "192.0.2.1"}, {Type: "AAAA", Value: "2001:db8::1"}}

	w := New(nil, true, FormatText)
	w.SetPlain(true)
	out := captureStdout(t, func() { w.Result("www.example.com", recs) })
	if out != "www.example.com\n" {
		t.Errorf("plain stdout = %q, want bare name", out)
	}

	var buf strings.Builder
	bw := bufio.NewWriter(&buf)
	w = New(bw, false, FormatText)
	w.SetPlain(true)
	w.SetShowRecords(true)
	out = captureStdout(t, func() { w.Result("www.example.com", recs) })
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	want := "www.example.com A=192.0.2.1 AAAA=2001:db8::1\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
	if buf.String() != want {
		t.Errorf("file = %q, want %q", buf.String(), want)
	}
}

func TestWriterJSONLStreams(t *testing.T) {
	var buf strings.Builder
	bw := bufio.NewWriter(&buf)
	w := New(bw, false, FormatJSONL)
	out := captureStdout(t, func() {
		w.Result("a.example.com", []dns.Record{{Type: "A", Value: "192.0.2.1"}})
		w.Result("b.example.com", nil)
	})
	// Streamed before Finish: each line is a complete JSON object.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d stdout lines, want 2: %q", len(lines), out)
	}
	for _, l := range lines {
		var r Result
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("line %q is not valid JSON: %v", l, err)
		}
		if r.Records == nil {
			t.Errorf("line %q: records should be [] not null", l)
		}
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != strings.TrimSpace(out) {
		t.Errorf("file output %q differs from stdout %q", buf.String(), out)
	}
	if f, err := ParseFormat("jsonl"); err != nil || f != FormatJSONL {
		t.Errorf("ParseFormat(jsonl) = %v, %v", f, err)
	}
}

// lockedBuf is a goroutine-safe buffer for capturing stderr.
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// TestInfoDoesNotSpliceIntoProgress covers #36: verbose lines logged from many
// goroutines while the progress line redraws must each land on a clean line.
func TestInfoDoesNotSpliceIntoProgress(t *testing.T) {
	var buf lockedBuf
	w := New(nil, false, FormatText)
	w.stderr = &buf

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				w.Info("Resolved: host%d.example.com", i)
				w.Progress(50, int64(i), 100, 1)
			}
		}()
	}
	wg.Wait()
	w.ProgressDone()

	for _, line := range strings.Split(buf.b.String(), "\n") {
		// The visible text of a line is whatever follows its last carriage return.
		visible := strings.TrimSpace(line[strings.LastIndex(line, "\r")+1:])
		if strings.Contains(line, "Resolved:") && !strings.HasPrefix(visible, "Resolved:") {
			t.Fatalf("verbose line spliced into progress output: %q", line)
		}
	}
}

// failWriter accepts limit bytes, then fails every write, like a disk filling
// up mid-scan.
type failWriter struct{ limit int }

func (f *failWriter) Write(p []byte) (int, error) {
	if len(p) <= f.limit {
		f.limit -= len(p)
		return len(p), nil
	}
	n := f.limit
	f.limit = 0
	return n, io.ErrShortWrite
}

// TestFinishReportsFileWriteErrors covers #30: an output file that cannot be
// fully written must surface an error from Finish for every format, so the
// CLI can exit non-zero and the TUI can warn.
func TestFinishReportsFileWriteErrors(t *testing.T) {
	for _, format := range []Format{FormatText, FormatJSON, FormatCSV, FormatJSONL} {
		buf := bufio.NewWriterSize(&failWriter{limit: 8}, 16)
		w := NewFile(buf, false, format)
		for i := 0; i < 20; i++ {
			w.Result("host"+strings.Repeat("x", i)+".example.com", []dns.Record{{Type: "A", Value: "192.0.2.1"}})
		}
		if err := w.Finish(); err == nil {
			t.Errorf("format %d: Finish returned nil after the file writer failed", format)
		}
	}
}
