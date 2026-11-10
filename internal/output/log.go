package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/TMHSDigital/subenum/internal/scan"
)

// LogFormat selects how diagnostics (notices, warnings, errors, verbose
// lines and the progress line) are written to stderr. Results on stdout are
// not affected (#198).
type LogFormat int

const (
	// LogText is the default: free-text lines, as a person reads them.
	LogText LogFormat = iota
	// LogJSON writes every diagnostic as one JSON object per line (JSONL).
	LogJSON
)

// ParseLogFormat converts a -log-format value into a LogFormat.
func ParseLogFormat(s string) (LogFormat, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text":
		return LogText, nil
	case "json", "jsonl":
		return LogJSON, nil
	default:
		return LogText, fmt.Errorf("invalid -log-format %q (want text or json)", s)
	}
}

// Diagnostic levels in -log-format json.
const (
	LevelError  = "error"
	LevelWarn   = "warn"
	LevelNotice = "notice" // shown even under -silent
	LevelInfo   = "info"
	LevelDebug  = "debug" // -v lookup lines
)

// Diagnostic kinds in -log-format json. Engine notices use their own
// category instead (wildcard, cap, ceiling, skip).
const (
	KindMessage  = "message"  // any other diagnostic
	KindScan     = "scan"     // an error reported by the scan engine
	KindVerbose  = "verbose"  // a -v lookup line
	KindProgress = "progress" // a progress tick
)

// logEntry is one -log-format json line.
type logEntry struct {
	Time     string         `json:"time"`
	Level    string         `json:"level"`
	Kind     string         `json:"kind"`
	Target   string         `json:"target,omitempty"`
	Message  string         `json:"message"`
	Settings []scan.Setting `json:"settings,omitempty"`
	Progress *logProgress   `json:"progress,omitempty"`
}

// logProgress is the payload of a progress event.
type logProgress struct {
	Percent    float64 `json:"percent"`
	Processed  int64   `json:"processed"`
	Total      int64   `json:"total"`
	Found      int64   `json:"found"`
	ETASeconds *int64  `json:"eta_seconds,omitempty"`
}

// SetLogFormat selects text or JSON diagnostics on stderr (#198).
func (w *Writer) SetLogFormat(f LogFormat) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logJSON = f == LogJSON
}

// LogJSON reports whether diagnostics are written as JSON lines.
func (w *Writer) LogJSON() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.logJSON
}

// SetTarget names the domain being scanned, carried as "target" by every
// JSON diagnostic until it is changed; "" leaves it out. Targets are scanned
// one at a time, so one current target is enough.
func (w *Writer) SetTarget(domain string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.target = domain
}

// textPrefixes are the free-text markers a JSON line carries as its level
// instead of in its message. An empty level keeps the caller's.
var textPrefixes = []struct{ prefix, level string }{
	{"Error: ", LevelError},
	{"Warning: ", LevelWarn},
	{"WARNING: ", LevelWarn},
	{"Note: ", ""},
}

// diagLocked writes one diagnostic. text is exactly what text mode prints
// (without the newline). In JSON mode a leading marker such as "Warning: "
// becomes the level, and a blank line, which only spaces out text output, is
// dropped.
func (w *Writer) diagLocked(level, kind, text string, settings []scan.Setting) {
	w.clearProgressLocked()
	if !w.logJSON {
		_, _ = fmt.Fprintln(w.errOut(), text)
		return
	}
	msg := text
	for _, p := range textPrefixes {
		if rest, ok := strings.CutPrefix(msg, p.prefix); ok {
			msg = rest
			if p.level != "" && level != LevelError {
				level = p.level
			}
			break
		}
	}
	// Indentation only aligns text columns.
	if msg = strings.TrimSpace(msg); msg == "" {
		return
	}
	w.writeLogLocked(logEntry{Level: level, Kind: kind, Message: msg, Settings: settings})
}

// writeLogLocked encodes e as one line on stderr.
func (w *Writer) writeLogLocked(e logEntry) {
	now := time.Now
	if w.now != nil {
		now = w.now
	}
	e.Time = now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	e.Target = w.target
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return // only strings and numbers: cannot fail
	}
	_, _ = w.errOut().Write(buf.Bytes())
}

// progressJSONLocked writes a progress tick as a JSON event.
func (w *Writer) progressJSONLocked(line string, pct float64, processed, total, found int64, left time.Duration, etaOK bool) {
	p := &logProgress{Percent: math.Round(pct*10) / 10, Processed: processed, Total: total, Found: found}
	if etaOK {
		secs := int64(math.Ceil(left.Seconds()))
		p.ETASeconds = &secs
	}
	w.writeLogLocked(logEntry{Level: LevelInfo, Kind: KindProgress, Message: strings.TrimSpace(line), Progress: p})
}

// Verbose writes a -v lookup line: level debug, kind verbose in JSON. It is
// quiet under SetQuiet like Info.
func (w *Writer) Verbose(format string, a ...any) {
	if w.quiet {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.diagLocked(LevelDebug, KindVerbose, fmt.Sprintf(format, a...), nil)
}

// NoticeOf is Notice with a kind for JSON output, such as "simulation".
func (w *Writer) NoticeOf(kind, format string, a ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.diagLocked(LevelNotice, kind, fmt.Sprintf(format, a...), nil)
}

// ScanNotice writes an engine notice. msg is the engine's text with its
// {setting} tokens, rendered as flag names; JSON output also lists the
// settings as codes. kind is the notice category. Quiet under SetQuiet.
func (w *Writer) ScanNotice(kind, msg string) {
	if w.quiet {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.diagLocked(LevelWarn, kind, scan.Render(msg, scan.FlagName), scan.SettingsIn(msg))
}

// ScanError writes an engine error like Error, with its {setting} tokens
// rendered as flag names and listed as codes in JSON output. It returns the
// rendered message.
func (w *Writer) ScanError(msg string) string {
	text := scan.Render(msg, scan.FlagName)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.diagLocked(LevelError, KindScan, "Error: "+text, scan.SettingsIn(msg))
	return text
}
