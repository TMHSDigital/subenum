package output

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// SummarySchema versions the Summary object. Fields may be added without a
// bump; renaming or removing one, or changing its meaning, bumps it (#70).
const SummarySchema = 1

// Summary is the machine-readable run-quality report: what was scanned, how
// many queries were sent, how every lookup ended, and a verdict on how far the
// results can be trusted. It is written by -stats and, in jsonl format, as the
// last line of the output.
type Summary struct {
	Type        string          `json:"type"` // always "summary"
	Schema      int             `json:"schema"`
	Tool        string          `json:"tool"`
	Version     string          `json:"version"`
	Started     time.Time       `json:"started"`
	DurationMs  int64           `json:"duration_ms"`
	Simulated   bool            `json:"simulated"`
	Seed        uint64          `json:"seed,omitempty"`
	Resolver    string          `json:"resolver,omitempty"`
	RateLimit   int             `json:"rate_limit"`
	QueriesSent int64           `json:"queries_sent"`
	AchievedQPS float64         `json:"achieved_qps"`
	Verdict     string          `json:"verdict"`
	Reason      string          `json:"reason"`
	Targets     []TargetSummary `json:"targets"`
}

// TargetSummary is one scanned domain's part of a Summary.
type TargetSummary struct {
	Domain      string       `json:"domain"`
	Status      string       `json:"status"` // ok, failed, skipped, interrupted, not_run
	Error       string       `json:"error,omitempty"`
	Processed   int64        `json:"processed"`
	Total       int64        `json:"total"`
	Found       int64        `json:"found"`
	Outcomes    Outcomes     `json:"outcomes"`
	QueriesSent int64        `json:"queries_sent"`
	SkippedCap  int64        `json:"skipped_by_cap"`
	Wildcard    bool         `json:"wildcard"`
	Fingerprint []dns.Record `json:"wildcard_fingerprint,omitempty"`
	Verdict     string       `json:"verdict"`
	Reason      string       `json:"reason"`
}

// Outcomes counts how each lookup ended. SERVFAIL and other errors Go's
// resolver does not distinguish are counted under Other.
type Outcomes struct {
	Resolved         int64 `json:"resolved"`
	NXDomain         int64 `json:"nxdomain"`
	Timeout          int64 `json:"timeout"`
	Refused          int64 `json:"refused"`
	Other            int64 `json:"other"`
	WildcardFiltered int64 `json:"wildcard_filtered"`
	Excluded         int64 `json:"excluded"` // out of scope (-exclude); never queried
}

// Summary writes s as the final line of jsonl output (stdout and the -o
// file). Other formats ignore it; use -stats for those.
func (w *Writer) Summary(s Summary) {
	if w.format != FormatJSONL {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	data, err := json.Marshal(s)
	if err != nil {
		_, _ = fmt.Fprintf(w.errOut(), "Error: encoding summary: %v\n", err)
		return
	}
	if w.stdout {
		w.clearProgressLocked()
		fmt.Printf("%s\n", data)
	}
	if w.outWriter != nil {
		_, _ = fmt.Fprintf(w.outWriter, "%s\n", data)
	}
}

// WriteSummaryFile writes s as indented JSON to path, atomically.
func WriteSummaryFile(path string, s Summary) error {
	f, err := CreateFile(path)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		_ = f.Close(false)
		return err
	}
	_, werr := f.Write(append(data, '\n'))
	if cerr := f.Close(werr == nil); werr == nil {
		werr = cerr
	}
	return werr
}
