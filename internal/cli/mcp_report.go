package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/mcp"
	"github.com/TMHSDigital/subenum/pkg/subenum"
)

// mcpReport is what lab_scan and scan return, as JSON.
type mcpReport struct {
	Domain     string      `json:"domain"`
	Scenario   string      `json:"scenario,omitempty"`
	Verdict    string      `json:"verdict"`
	Reason     string      `json:"reason"`
	Error      string      `json:"error,omitempty"`
	Found      int         `json:"found"`
	Results    []mcpResult `json:"results"`
	Outcomes   mcpOutcomes `json:"outcomes"`
	Skipped    int64       `json:"skipped_by_cap,omitempty"`
	NextOffset int         `json:"next_offset,omitempty"` // the offset that continues a scan max_queries cut short
	Excluded   int64       `json:"excluded,omitempty"`
	Retried    int64       `json:"retried,omitempty"`   // retry_inconclusive looked these up again
	Recovered  int64       `json:"recovered,omitempty"` // and these then got an answer
	Backoffs   int64       `json:"rate_backoffs,omitempty"`
	Wildcard   bool        `json:"wildcard,omitempty"`
	Notices    []string    `json:"notices,omitempty"`
	Sources    []mcpSource `json:"sources,omitempty"`
	MaxQueries int         `json:"max_queries"`
	Rate       int         `json:"rate,omitempty"`
}

// mcpSource is what one passive source proposed, or the error it hit.
type mcpSource struct {
	Name      string `json:"name"`
	Names     int    `json:"names"`
	Error     string `json:"error,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type mcpResult struct {
	Name     string   `json:"name"`
	Records  []string `json:"records"`
	Takeover string   `json:"takeover,omitempty"`
	Internal string   `json:"internal,omitempty"`
}

type mcpOutcomes struct {
	NXDomain         int64 `json:"nxdomain"`
	Timeout          int64 `json:"timeout"`
	Refused          int64 `json:"refused"`
	Other            int64 `json:"other"`
	WildcardFiltered int64 `json:"wildcard_filtered"`
}

// runMCPScan runs one scan and reports it. offset is where cfg.Words starts
// in the call's word list, for the report's next_offset.
func runMCPScan(ctx context.Context, cfg subenum.Config, offset int) *mcpReport {
	report := &mcpReport{Domain: cfg.Domain, Results: []mcpResult{}, MaxQueries: cfg.MaxQueries, Rate: cfg.Rate}
	cfg.Logf = func(string, ...any) {} // standard output carries the protocol
	events, err := subenum.Run(ctx, cfg)
	if err != nil {
		report.Verdict, report.Reason, report.Error = verdictNotRun, "the scan did not start; see error", err.Error()
		return report
	}
	var stats subenum.Stats
	for ev := range events {
		switch ev.Kind {
		case subenum.KindResult:
			r := mcpResult{Name: ev.Result.Name, Records: []string{}, Takeover: ev.Result.Takeover, Internal: ev.Result.Internal}
			for _, rec := range ev.Result.Records {
				r.Records = append(r.Records, rec.Type+" "+rec.Value)
			}
			report.Results = append(report.Results, r)
		case subenum.KindProgress:
			mcp.ReportProgress(ctx, float64(ev.Processed), float64(ev.Total),
				fmt.Sprintf("%d/%d tested, %d found", ev.Processed, ev.Total, ev.Found))
		case subenum.KindNotice:
			report.Notices = append(report.Notices, ev.Message)
		case subenum.KindError:
			// Only a fatal error is the report's error; mcpVerdict reads it
			// as the scan having failed.
			if ev.Fatal && report.Error == "" {
				report.Error = ev.Message
			}
		case subenum.KindDone:
			stats = ev.Stats
		}
	}
	report.Found = len(report.Results)
	report.Outcomes = mcpOutcomes{NXDomain: stats.NXDomain, Timeout: stats.Timeout, Refused: stats.Refused, Other: stats.Other, WildcardFiltered: stats.WildcardFiltered}
	report.Skipped = stats.Skipped
	report.Excluded, report.Retried, report.Recovered, report.Backoffs = stats.Excluded, stats.Retried, stats.Recovered, stats.RateBackoffs
	report.Wildcard = stats.Wildcard
	report.Verdict, report.Reason = mcpVerdict(stats, report.Error, ctx.Err() != nil)
	if report.NextOffset = nextOffset(cfg, stats, offset); report.NextOffset > 0 {
		report.Reason += fmt.Sprintf("; call again with offset %d to test the words after these", report.NextOffset)
	}
	return report
}

// mcpReasonTerms renders the Config fields a verdict reason names in the
// terms an agent sees: its own max_queries argument, the operator's
// -max-duration.
var mcpReasonTerms = strings.NewReplacer("MaxQueries", "max_queries", "MaxDuration", "the server's -max-duration")

// mcpVerdict is a scan's verdict for the agent. It is the library's verdict
// (the CLI report's rules, #263) with two additions for a report that has
// no status field: an error before any name was tested is not_run, and an
// error after an otherwise complete scan is unreliable.
func mcpVerdict(stats subenum.Stats, errMsg string, interrupted bool) (verdict, reason string) {
	verdict, reason = stats.Verdict(interrupted)
	switch {
	case interrupted && stats.Total() == 0 && errMsg == "":
		// Cancelled during the preflight or the wildcard probes (#241).
		return verdictNotRun, "the scan was cancelled before testing any name"
	case errMsg != "" && stats.Total() == 0:
		// A wildcard zone, a failed resolver check: nothing was tested.
		return verdictNotRun, "the scan stopped before testing any name; see error"
	case errMsg != "" && verdict == subenum.VerdictComplete:
		return subenum.VerdictUnreliable, "the scan stopped early; see error"
	}
	return verdict, mcpReasonTerms.Replace(reason)
}

func (r *mcpReport) result() mcp.Result {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return mcp.Errorf("encoding the report: %v", err)
	}
	return mcp.Result{Text: string(b), IsError: r.Error != "", Structured: r}
}

// mcpDiffReport is what diff returns, as JSON (#333).
type mcpDiffReport struct {
	Added           []mcpDiffName `json:"added"`
	Missing         []mcpDiffName `json:"missing"`
	Changed         []mcpDiffName `json:"changed"`
	RecordsCompared bool          `json:"records_compared"`
	Notes           []string      `json:"notes"`
}

// mcpDiffName is one name diff reports, with its records in mcpResult's
// "TYPE value" form: current records for added and changed names, previous
// records for missing ones.
type mcpDiffName struct {
	Name            string   `json:"name"`
	Records         []string `json:"records"`
	PreviousRecords []string `json:"previous_records,omitempty"`
}

// mcpDiff compares two result sets for the diff tool.
func mcpDiff(prev, cur baseline, types []string) *mcpDiffReport {
	d := compareBaselines(prev, cur, true, types)
	strs := func(recs []dns.Record) []string {
		out := []string{}
		for _, r := range recs {
			out = append(out, r.Type+" "+r.Value)
		}
		return out
	}
	list := func(names []string, records map[string][]dns.Record, previous map[string][]dns.Record) []mcpDiffName {
		out := []mcpDiffName{}
		for _, name := range names {
			n := mcpDiffName{Name: name, Records: strs(records[name])}
			if previous != nil {
				n.PreviousRecords = strs(previous[name])
			}
			out = append(out, n)
		}
		return out
	}
	r := &mcpDiffReport{
		Added:           list(d.added, cur.records, nil),
		Missing:         list(d.missing, prev.records, nil),
		Changed:         list(d.changed, cur.records, prev.records),
		RecordsCompared: d.compared,
		Notes: []string{"Missing names were in previous but not in current. Nothing was looked up, so they are unverified: " +
			"a name may be missing because the later scan did not try it or did not complete, not because it is gone."},
	}
	if !d.compared {
		r.Notes = append(r.Notes, "Records were not compared because a result set has none (text format): changed is empty.")
	}
	return r
}

func (r *mcpDiffReport) result() mcp.Result {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return mcp.Errorf("encoding the report: %v", err)
	}
	return mcp.Result{Text: string(b), Structured: r}
}

// mcpDiffSchema is diff's outputSchema: mcpDiffReport as JSON Schema.
// TestMCPDiffSchemaCoversTheReport keeps the two in step.
var mcpDiffSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "added": {"type": "array", "items": ` + mcpDiffNameSchema + `, "description": "names in current but not in previous"},
    "missing": {"type": "array", "items": ` + mcpDiffNameSchema + `, "description": "names in previous but not in current; unverified, since nothing was looked up"},
    "changed": {"type": "array", "items": ` + mcpDiffNameSchema + `, "description": "names in both whose records differ"},
    "records_compared": {"type": "boolean", "description": "false when a result set has no records, so changed is empty"},
    "notes": {"type": "array", "items": {"type": "string"}}
  },
  "required": ["added", "missing", "changed", "records_compared", "notes"]
}`)

// mcpDiffNameSchema is mcpDiffName as JSON Schema.
const mcpDiffNameSchema = `{
      "type": "object",
      "properties": {
        "name": {"type": "string"},
        "records": {"type": "array", "items": {"type": "string"}, "description": "\"TYPE value\": current records, or previous ones for a missing name"},
        "previous_records": {"type": "array", "items": {"type": "string"}, "description": "changed names only"}
      },
      "required": ["name", "records"]
    }`

// mcpReportSchema is the outputSchema of scan and lab_scan: mcpReport as
// JSON Schema (#270). TestMCPReportSchemaCoversTheReport keeps the two in
// step.
var mcpReportSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "domain": {"type": "string"},
    "scenario": {"type": "string", "description": "lab_scan only"},
    "verdict": {"enum": ["complete", "degraded", "unreliable", "not_run"]},
    "reason": {"type": "string"},
    "error": {"type": "string"},
    "found": {"type": "integer"},
    "results": {"type": "array", "items": {
      "type": "object",
      "properties": {
        "name": {"type": "string"},
        "records": {"type": "array", "items": {"type": "string"}, "description": "\"TYPE value\", such as \"A 192.0.2.10\""},
        "takeover": {"type": "string"},
        "internal": {"type": "string"}
      },
      "required": ["name", "records"]
    }},
    "outcomes": {"type": "object", "properties": {
      "nxdomain": {"type": "integer"},
      "timeout": {"type": "integer"},
      "refused": {"type": "integer"},
      "other": {"type": "integer"},
      "wildcard_filtered": {"type": "integer"}
    }},
    "skipped_by_cap": {"type": "integer"},
    "next_offset": {"type": "integer", "description": "max_queries left words untested: call again with the same words and this offset to test the following ones"},
    "excluded": {"type": "integer"},
    "retried": {"type": "integer"},
    "recovered": {"type": "integer"},
    "rate_backoffs": {"type": "integer"},
    "wildcard": {"type": "boolean"},
    "notices": {"type": "array", "items": {"type": "string"}},
    "sources": {"type": "array", "items": {
      "type": "object",
      "properties": {"name": {"type": "string"}, "names": {"type": "integer"}, "error": {"type": "string"}, "truncated": {"type": "boolean", "description": "the source hit one of its limits: its names were used, but some hosts may be missing"}},
      "required": ["name", "names"]
    }},
    "max_queries": {"type": "integer"},
    "rate": {"type": "integer"}
  },
  "required": ["domain", "verdict", "reason", "found", "results", "outcomes", "max_queries"]
}`)
