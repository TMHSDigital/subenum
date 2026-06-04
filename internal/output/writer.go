package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// Format selects how resolved results are rendered on stdout and in the output
// file.
type Format int

const (
	// FormatText is the default human-friendly streaming output.
	FormatText Format = iota
	// FormatJSON buffers results and emits a single JSON array at completion.
	FormatJSON
	// FormatCSV streams "subdomain,type,value" rows with a header.
	//
	// Note: the JSON format buffers the whole document and therefore does not
	// stream like text and CSV do. If live JSON piping is ever needed, JSONL
	// (one JSON object per line) is the streaming-friendly alternative.
	FormatCSV
)

// ParseFormat converts a flag string into a Format.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	case "csv":
		return FormatCSV, nil
	default:
		return FormatText, fmt.Errorf("invalid format %q (want text, json, or csv)", s)
	}
}

// Result is one resolved subdomain and its records, used for structured output.
type Result struct {
	Subdomain string       `json:"subdomain"`
	Records   []dns.Record `json:"records"`
}

// Writer synchronises all output. Results go to stdout (and optionally a file);
// everything else (progress, verbose, errors) goes to stderr.
type Writer struct {
	mu        sync.Mutex
	outWriter *bufio.Writer
	simulate  bool
	format    Format

	buffered  []Result // FormatJSON: accumulated until Finish
	csvStdout *csv.Writer
	csvFile   *csv.Writer
	csvInit   bool
}

// New returns a Writer. If outWriter is non-nil, resolved domains are also
// written there. Set simulate to true to tag text result lines as simulated.
func New(outWriter *bufio.Writer, simulate bool, format Format) *Writer {
	return &Writer{outWriter: outWriter, simulate: simulate, format: format}
}

// Result records a resolved domain. In text mode it prints immediately; in JSON
// mode it is buffered for Finish; in CSV mode rows are streamed.
func (w *Writer) Result(domain string, records []dns.Record) {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.format {
	case FormatJSON:
		w.buffered = append(w.buffered, Result{Subdomain: domain, Records: records})
	case FormatCSV:
		w.writeCSVRows(domain, records)
	default:
		w.writeText(domain)
	}
}

func (w *Writer) writeText(domain string) {
	if w.simulate {
		fmt.Printf("Found (SIMULATED): %s\n", domain)
	} else {
		fmt.Printf("Found: %s\n", domain)
	}
	if w.outWriter != nil {
		fmt.Fprintln(w.outWriter, domain)
	}
}

func (w *Writer) ensureCSV() {
	if w.csvInit {
		return
	}
	w.csvInit = true
	w.csvStdout = csv.NewWriter(os.Stdout)
	header := []string{"subdomain", "type", "value"}
	_ = w.csvStdout.Write(header)
	if w.outWriter != nil {
		w.csvFile = csv.NewWriter(w.outWriter)
		_ = w.csvFile.Write(header)
	}
}

func (w *Writer) writeCSVRows(domain string, records []dns.Record) {
	w.ensureCSV()
	rows := records
	if len(rows) == 0 {
		rows = []dns.Record{{}}
	}
	for _, r := range rows {
		row := []string{domain, r.Type, r.Value}
		_ = w.csvStdout.Write(row)
		if w.csvFile != nil {
			_ = w.csvFile.Write(row)
		}
	}
}

// Finish flushes any buffered or streamed structured output. It must be called
// once after the scan completes (before the output file is flushed and closed).
func (w *Writer) Finish() {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.format {
	case FormatJSON:
		results := w.buffered
		if results == nil {
			results = []Result{}
		}
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: encoding JSON output: %v\n", err)
			return
		}
		fmt.Printf("%s\n", data)
		if w.outWriter != nil {
			fmt.Fprintf(w.outWriter, "%s\n", data)
		}
	case FormatCSV:
		if w.csvStdout != nil {
			w.csvStdout.Flush()
		}
		if w.csvFile != nil {
			w.csvFile.Flush()
		}
	}
}

// Progress writes a progress line to stderr using carriage-return overwrite.
func (w *Writer) Progress(pct float64, processed, total, found int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\rProgress: %.1f%% (%d/%d) | Found: %d ",
		pct, processed, total, found)
}

// ProgressDone writes the final newline on stderr after progress reporting ends.
func (w *Writer) ProgressDone() {
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprintln(os.Stderr)
}

// Info writes an informational line to stderr.
func (w *Writer) Info(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

// Error writes an error line to stderr.
func (w *Writer) Error(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", a...)
}
