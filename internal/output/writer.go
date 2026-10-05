package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
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
	FormatCSV
	// FormatJSONL streams one JSON object per resolved subdomain, one per line.
	// Unlike FormatJSON it needs no Finish to be complete, so it pipes live.
	FormatJSONL
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
	case "jsonl", "ndjson":
		return FormatJSONL, nil
	default:
		return FormatText, fmt.Errorf("invalid format %q (want text, json, jsonl, or csv)", s)
	}
}

// Result is one resolved subdomain and its records, used for structured output.
// Simulated is set on every result of a -simulate run, so invented names can
// never pass for real recon output once saved or piped (#53).
type Result struct {
	Subdomain string       `json:"subdomain"`
	Records   []dns.Record `json:"records"`
	Simulated bool         `json:"simulated,omitempty"`
}

// Writer synchronises all output. Results go to stdout (and optionally a file);
// everything else (progress, verbose, errors) goes to stderr.
type Writer struct {
	mu        sync.Mutex
	outWriter *bufio.Writer
	simulate  bool
	format    Format
	stdout    bool // mirror results to os.Stdout (false for the TUI)
	plain     bool // text stdout prints bare names, no "Found:" banner
	records   bool // text output appends record types and values

	stderr      io.Writer // diagnostics destination; nil means os.Stderr
	progressLen int       // width of the progress line currently on screen
	lineMode    bool      // progress as whole lines, never carriage-return overwrites (#78)

	seed       uint64 // simulation seed, named in the text file header
	headerDone bool   // text file header written

	buffered  []Result // FormatJSON: accumulated until Finish
	csvStdout *csv.Writer
	csvFile   *csv.Writer
	csvInit   bool
}

// New returns a Writer that streams results to stdout. If outWriter is non-nil,
// resolved domains are also written there. Set simulate to true to tag text
// result lines as simulated.
func New(outWriter *bufio.Writer, simulate bool, format Format) *Writer {
	return &Writer{outWriter: outWriter, simulate: simulate, format: format, stdout: true}
}

// NewFile returns a Writer that writes only to outWriter, never to stdout. The
// TUI uses this so structured results land in the chosen file while the
// alt-screen viewport keeps full ownership of the terminal.
func NewFile(outWriter *bufio.Writer, simulate bool, format Format) *Writer {
	return &Writer{outWriter: outWriter, simulate: simulate, format: format, stdout: false}
}

// SetPlain makes text-mode stdout print bare subdomain names, one per line,
// without the "Found:" banner, so output pipes straight into other tools. The
// CLI enables it when stdout is not a terminal.
func (w *Writer) SetPlain(plain bool) { w.plain = plain }

// SetProgressLines makes Progress print complete newline-terminated lines
// instead of redrawing one line with carriage returns. The CLI enables it when
// stderr is not a terminal, so logs that merge stdout and stderr never get a
// result glued onto a progress line (#78).
func (w *Writer) SetProgressLines(lines bool) { w.lineMode = lines }

// SetSeed records the simulation seed for the simulated-results file header.
func (w *Writer) SetSeed(seed uint64) { w.seed = seed }

// SetShowRecords makes text-mode output (stdout and file) append each
// result's records as TYPE=value pairs.
func (w *Writer) SetShowRecords(show bool) { w.records = show }

// Result records a resolved domain. In text mode it prints immediately; in JSON
// mode it is buffered for Finish; in CSV and JSONL mode it is streamed.
func (w *Writer) Result(domain string, records []dns.Record) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// stdout and the stderr progress line may share a screen or a merged
	// stream; blank the progress line so the result starts on a clean line.
	if w.stdout {
		w.clearProgressLocked()
	}

	switch w.format {
	case FormatJSON:
		w.buffered = append(w.buffered, Result{Subdomain: domain, Records: records, Simulated: w.simulate})
	case FormatCSV:
		w.writeCSVRows(domain, records)
	case FormatJSONL:
		w.writeJSONL(domain, records)
	default:
		w.writeText(domain, records)
	}
}

func (w *Writer) writeText(domain string, records []dns.Record) {
	line := domain
	if w.records {
		line += formatRecords(records)
	}
	if w.stdout {
		switch {
		case w.plain:
			fmt.Println(line)
		case w.simulate:
			fmt.Printf("Found (SIMULATED): %s\n", line)
		default:
			fmt.Printf("Found: %s\n", line)
		}
	}
	if w.outWriter != nil {
		w.writeTextHeaderLocked()
		fmt.Fprintln(w.outWriter, line)
	}
}

// writeTextHeaderLocked starts a simulated text results file with a comment
// line, so the file identifies itself wherever it ends up (#53). subenum's own
// wordlist reader skips # lines, so the file still loads as a wordlist.
func (w *Writer) writeTextHeaderLocked() {
	if w.headerDone || !w.simulate || w.format != FormatText || w.outWriter == nil {
		return
	}
	w.headerDone = true
	fmt.Fprintf(w.outWriter, "# SIMULATED - not real DNS results (subenum -simulate -seed %d)\n", w.seed)
}

// formatRecords renders records as " A=192.0.2.1 AAAA=2001:db8::1".
func formatRecords(records []dns.Record) string {
	var b strings.Builder
	for _, r := range records {
		b.WriteString(" " + r.Type + "=" + r.Value)
	}
	return b.String()
}

func (w *Writer) writeJSONL(domain string, records []dns.Record) {
	if records == nil {
		records = []dns.Record{}
	}
	data, err := json.Marshal(Result{Subdomain: domain, Records: records, Simulated: w.simulate})
	if err != nil {
		fmt.Fprintf(w.errOut(), "Error: encoding JSON output: %v\n", err)
		return
	}
	if w.stdout {
		fmt.Printf("%s\n", data)
	}
	if w.outWriter != nil {
		fmt.Fprintf(w.outWriter, "%s\n", data)
	}
}

func (w *Writer) ensureCSV() {
	if w.csvInit {
		return
	}
	w.csvInit = true
	header := []string{"subdomain", "type", "value"}
	if w.simulate {
		header = append(header, "simulated")
	}
	if w.stdout {
		w.csvStdout = csv.NewWriter(os.Stdout)
		_ = w.csvStdout.Write(header)
	}
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
		if w.simulate {
			row = append(row, "true")
		}
		if w.csvStdout != nil {
			_ = w.csvStdout.Write(row)
		}
		if w.csvFile != nil {
			_ = w.csvFile.Write(row)
		}
	}
}

// Finish flushes any buffered or streamed structured output. It must be called
// once after the scan completes (before the output file is flushed and closed).
// It returns the first error writing to the output file, so callers can report
// an incomplete results file instead of exiting successfully. Errors writing to
// stdout (for example a closed pipe) are not reported here.
func (w *Writer) Finish() error {
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
			return fmt.Errorf("encoding JSON output: %w", err)
		}
		if w.stdout {
			fmt.Printf("%s\n", data)
		}
		if w.outWriter != nil {
			if _, err := fmt.Fprintf(w.outWriter, "%s\n", data); err != nil {
				return err
			}
		}
	case FormatText:
		w.writeTextHeaderLocked() // a simulated run with no hits still says so
	case FormatCSV:
		if w.csvStdout != nil {
			w.csvStdout.Flush()
		}
		if w.csvFile != nil {
			w.csvFile.Flush()
			if err := w.csvFile.Error(); err != nil {
				return err
			}
		}
	}
	if w.outWriter != nil {
		return w.outWriter.Flush()
	}
	return nil
}

// errOut is where diagnostics go; tests may swap it.
func (w *Writer) errOut() io.Writer {
	if w.stderr != nil {
		return w.stderr
	}
	return os.Stderr
}

// Progress writes a progress line to stderr using carriage-return overwrite,
// or as a complete line when SetProgressLines is on.
func (w *Writer) Progress(pct float64, processed, total, found int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	line := fmt.Sprintf("Progress: %.1f%% (%d/%d) | Found: %d ", pct, processed, total, found)
	if w.lineMode {
		_, _ = fmt.Fprintln(w.errOut(), strings.TrimSpace(line))
		return
	}
	// Pad over a longer previous line so no stale characters remain.
	pad := max(0, w.progressLen-len(line))
	_, _ = fmt.Fprint(w.errOut(), "\r"+line+strings.Repeat(" ", pad))
	w.progressLen = len(line)
}

// ProgressDone ends the progress line with a newline on stderr.
func (w *Writer) ProgressDone() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.progressLen > 0 {
		fmt.Fprintln(w.errOut())
		w.progressLen = 0
	}
}

// clearProgressLocked blanks the in-place progress line so a diagnostic can be
// printed on a clean line; the next progress tick redraws it. Overwriting with
// spaces instead of an ANSI erase keeps legacy Windows consoles working.
func (w *Writer) clearProgressLocked() {
	if w.progressLen > 0 {
		_, _ = fmt.Fprint(w.errOut(), "\r"+strings.Repeat(" ", w.progressLen)+"\r")
		w.progressLen = 0
	}
}

// Info writes an informational line to stderr. It is serialized with the
// progress line, so concurrent verbose logging cannot splice into it (#36).
func (w *Writer) Info(format string, a ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.clearProgressLocked()
	fmt.Fprintf(w.errOut(), format+"\n", a...)
}

// Error writes an error line to stderr, serialized like Info.
func (w *Writer) Error(format string, a ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.clearProgressLocked()
	fmt.Fprintf(w.errOut(), "Error: "+format+"\n", a...)
}
