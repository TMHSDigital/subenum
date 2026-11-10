// Package output renders scan results (text, JSON, JSONL, CSV) to stdout and
// the -o file, and serializes progress and diagnostics on stderr.
package output

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/scan"
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

// Result is one resolved subdomain as written: the engine's scan.Result
// (subdomain, records, simulated, takeover hint) plus what the CLI adds to it.
// The embedded fields come first, so the JSON field order is unchanged (#162).
type Result struct {
	scan.Result
	// Change is "added" or "removed" in -diff mode (#84), or "changed" with
	// -diff-records when a name's records differ from the baseline (#189).
	Change string `json:"change,omitempty"`
	// PreviousRecords are the baseline's records of a "changed" name.
	PreviousRecords []dns.Record `json:"previous_records,omitempty"`
	// Permutation marks a name found by the -permute pass (#72).
	Permutation bool `json:"permutation,omitempty"`
}

// Writer synchronises all output. Results go to stdout (and optionally a file);
// everything else (progress, verbose, errors) goes to stderr.
//
// Individual writes ignore their errors on purpose: outWriter is a
// bufio.Writer, whose errors are sticky and are returned by Finish and by the
// output file's Close, and a failed diagnostic write to stderr has nowhere
// better to be reported.
type Writer struct {
	mu        sync.Mutex
	outWriter *bufio.Writer
	simulate  bool
	format    Format
	stdout    bool      // mirror results to stdout (false for the TUI)
	out       io.Writer // stdout destination; nil means os.Stdout
	plain     bool      // text stdout prints bare names, no "Found:" banner
	records   bool      // text output appends record types and values

	stderr      io.Writer // diagnostics destination; nil means os.Stderr
	progressLen int       // width of the progress line currently on screen
	lineMode    bool      // progress as whole lines, never carriage-return overwrites (#78)
	quiet       bool      // -silent: Info and Progress print nothing (#128)
	eta         ETA       // time left, appended to the progress line (#191)
	logJSON     bool      // -log-format json: diagnostics as JSON lines (#198)
	target      string    // the domain being scanned, for JSON diagnostics
	now         func() time.Time

	seed           uint64 // simulation seed, named in the text file header
	takeoverColumn bool   // CSV carries a takeover_candidate column
	diff           bool   // -diff output: +/- prefixes and a CSV change column
	headerDone     bool   // text file header written

	jsonOpen  bool          // FormatJSON: the array's "[" and first element are written (#181)
	jsonBuf   bytes.Buffer  // FormatJSON: one element, reused
	jsonEnc   *json.Encoder // FormatJSON: writes into jsonBuf
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

// SetStdout sends results meant for stdout to out instead of os.Stdout, so
// the CLI can run against injected streams (#158). Call it before the first
// result.
func (w *Writer) SetStdout(out io.Writer) { w.out = out }

// SetStderr sends diagnostics, progress and notices to errOut instead of
// os.Stderr.
func (w *Writer) SetStderr(errOut io.Writer) { w.stderr = errOut }

// SetPlain makes text-mode stdout print bare subdomain names, one per line,
// without the "Found:" banner, so output pipes straight into other tools. The
// CLI enables it when stdout is not a terminal.
func (w *Writer) SetPlain(plain bool) { w.plain = plain }

// SetProgressLines makes Progress print complete newline-terminated lines
// instead of redrawing one line with carriage returns. The CLI enables it when
// stderr is not a terminal, so logs that merge stdout and stderr never get a
// result glued onto a progress line (#78).
func (w *Writer) SetProgressLines(lines bool) { w.lineMode = lines }

// SetQuiet makes Info and Progress print nothing, for -silent pipelines
// (#128). Error and Notice still print.
func (w *Writer) SetQuiet(quiet bool) { w.quiet = quiet }

// SetDiff switches to -diff output (#84): text lines get a "+ ", "- " or
// "~ " (changed) prefix and CSV gains a change column. JSON and JSONL carry
// Change as is.
func (w *Writer) SetDiff(on bool) { w.diff = on }

func diffPrefix(change string) string {
	switch change {
	case "removed":
		return "- "
	case "changed":
		return "~ "
	}
	return "+ "
}

// SetTakeoverColumn adds a takeover_candidate column to CSV output. The CLI
// sets it when CNAME records are requested, the only case that yields hints.
func (w *Writer) SetTakeoverColumn(on bool) { w.takeoverColumn = on }

// SetSeed records the simulation seed for the simulated-results file header.
func (w *Writer) SetSeed(seed uint64) { w.seed = seed }

// SetShowRecords makes text-mode output (stdout and file) append each
// result's records as TYPE=value pairs.
func (w *Writer) SetShowRecords(show bool) { w.records = show }

// Emit writes one result in the configured format. In text mode it prints
// immediately; in JSON mode it is streamed as an array element that Finish
// closes; in CSV and JSONL mode it is streamed. Simulated is set from the
// writer; Change marks a -diff result.
func (w *Writer) Emit(res Result) {
	w.mu.Lock()
	defer w.mu.Unlock()
	res.Simulated = w.simulate

	// stdout and the stderr progress line may share a screen or a merged
	// stream; blank the progress line so the result starts on a clean line.
	if w.stdout {
		w.clearProgressLocked()
	}

	switch w.format {
	case FormatJSON:
		w.writeJSONElement(res)
	case FormatCSV:
		w.writeCSVRows(res)
	case FormatJSONL:
		w.writeJSONL(res)
	default:
		w.writeText(res)
	}
}

func (w *Writer) writeText(res Result) {
	line := res.Subdomain
	if w.diff {
		line = diffPrefix(res.Change) + line
	}
	if w.records {
		line += formatRecords(res.Records)
		if res.Takeover != "" {
			line += " TAKEOVER?=" + res.Takeover
		}
		if len(res.PreviousRecords) > 0 {
			line += " (was" + formatRecords(res.PreviousRecords) + ")"
		}
	}
	if w.stdout {
		switch {
		case w.plain:
			_, _ = fmt.Fprintln(w.stdOut(), line)
		case w.simulate:
			_, _ = fmt.Fprintf(w.stdOut(), "Found (SIMULATED): %s\n", line)
		default:
			_, _ = fmt.Fprintf(w.stdOut(), "Found: %s\n", line)
		}
	}
	if w.outWriter != nil {
		w.writeTextHeaderLocked()
		_, _ = fmt.Fprintln(w.outWriter, line)
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
	_, _ = fmt.Fprintf(w.outWriter, "# SIMULATED - not real DNS results (subenum -simulate -seed %d)\n", w.seed)
}

// formatRecords renders records as " A=192.0.2.1 AAAA=2001:db8::1".
func formatRecords(records []dns.Record) string {
	var b strings.Builder
	for _, r := range records {
		b.WriteString(" " + r.Type + "=" + r.Value)
	}
	return b.String()
}

// writeJSONElement streams one element of the -format json array (#181).
// Each element is indented as json.MarshalIndent indents a whole slice, so
// the output is byte for byte what encoding every result at once gave,
// without holding the results or the document in memory.
// The encoder and its buffer are reused, so an element costs no garbage
// beyond what encoding/json itself pools.
func (w *Writer) writeJSONElement(res Result) {
	if w.jsonEnc == nil {
		w.jsonEnc = json.NewEncoder(&w.jsonBuf)
		w.jsonEnc.SetIndent("  ", "  ")
	}
	w.jsonBuf.Reset()
	if w.jsonOpen {
		w.jsonBuf.WriteString(",\n  ")
	} else {
		w.jsonBuf.WriteString("[\n  ")
	}
	if err := w.jsonEnc.Encode(res); err != nil {
		w.diagLocked(LevelError, KindMessage, "Error: encoding JSON output: "+err.Error(), nil)
		return
	}
	w.jsonOpen = true
	data := bytes.TrimSuffix(w.jsonBuf.Bytes(), []byte("\n")) // Encode ends each value with a newline
	if w.stdout {
		_, _ = w.stdOut().Write(data)
	}
	if w.outWriter != nil {
		_, _ = w.outWriter.Write(data)
	}
}

// Started reports whether -format json output has begun: its array is open
// and only Finish closes it, so a caller that skips Finish on an error path
// must still call it once Started is true.
func (w *Writer) Started() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.jsonOpen
}

func (w *Writer) writeJSONL(res Result) {
	if res.Records == nil {
		res.Records = []dns.Record{}
	}
	data, err := json.Marshal(res)
	if err != nil {
		w.diagLocked(LevelError, KindMessage, "Error: encoding JSON output: "+err.Error(), nil)
		return
	}
	if w.stdout {
		_, _ = fmt.Fprintf(w.stdOut(), "%s\n", data)
	}
	if w.outWriter != nil {
		_, _ = fmt.Fprintf(w.outWriter, "%s\n", data)
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
	if w.takeoverColumn {
		header = append(header, "takeover_candidate")
	}
	if w.diff {
		header = append(header, "change")
	}
	if w.stdout {
		w.csvStdout = csv.NewWriter(w.stdOut())
		_ = w.csvStdout.Write(header)
	}
	if w.outWriter != nil {
		w.csvFile = csv.NewWriter(w.outWriter)
		_ = w.csvFile.Write(header)
	}
}

func (w *Writer) writeCSVRows(res Result) {
	w.ensureCSV()
	rows := res.Records
	if len(rows) == 0 {
		rows = []dns.Record{{}}
	}
	for _, r := range rows {
		row := []string{res.Subdomain, r.Type, r.Value}
		if w.simulate {
			row = append(row, "true")
		}
		if w.takeoverColumn {
			row = append(row, res.Takeover)
		}
		if w.diff {
			row = append(row, res.Change)
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
		end := "\n]\n"
		if !w.jsonOpen {
			end = "[]\n"
		}
		w.jsonOpen = false
		if w.stdout {
			_, _ = io.WriteString(w.stdOut(), end)
		}
		if w.outWriter != nil {
			if _, err := w.outWriter.WriteString(end); err != nil {
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

// stdOut is where results meant for stdout go.
func (w *Writer) stdOut() io.Writer {
	if w.out != nil {
		return w.out
	}
	return os.Stdout
}

// errOut is where diagnostics go.
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
	if w.quiet {
		return
	}
	line := fmt.Sprintf("Progress: %.1f%% (%d/%d) | Found: %d ", pct, processed, total, found)
	left, etaOK := w.eta.Update(processed, total)
	if etaOK {
		line += "| ETA " + FormatETA(left) + " "
	}
	if w.logJSON {
		w.progressJSONLocked(line, pct, processed, total, found, left, etaOK)
		return
	}
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
		_, _ = fmt.Fprintln(w.errOut())
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
	if w.quiet {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.diagLocked(LevelInfo, KindMessage, fmt.Sprintf(format, a...), nil)
}

// Notice writes a line to stderr like Info, even under SetQuiet: for what a
// user must not miss, such as results being simulated.
func (w *Writer) Notice(format string, a ...any) {
	w.NoticeOf(KindMessage, format, a...)
}

// Error writes an error line to stderr, serialized like Info.
func (w *Writer) Error(format string, a ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.diagLocked(LevelError, KindMessage, "Error: "+fmt.Sprintf(format, a...), nil)
}
