package output

import (
	"bufio"
	"fmt"
	"os"
	"sync"
)

// Writer synchronises all output. Results go to stdout (and optionally a file);
// everything else (progress, verbose, errors) goes to stderr.
type Writer struct {
	mu        sync.Mutex
	outWriter *bufio.Writer
	simulate  bool
}

// New returns a Writer. If outWriter is non-nil, resolved domains are also
// written there. Set simulate to true to tag result lines as simulated.
func New(outWriter *bufio.Writer, simulate bool) *Writer {
	return &Writer{outWriter: outWriter, simulate: simulate}
}

// Result prints a resolved domain to stdout (and the output file if configured).
func (w *Writer) Result(domain string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.simulate {
		fmt.Printf("Found (SIMULATED): %s\n", domain)
	} else {
		fmt.Printf("Found: %s\n", domain)
	}
	if w.outWriter != nil {
		fmt.Fprintln(w.outWriter, domain)
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
