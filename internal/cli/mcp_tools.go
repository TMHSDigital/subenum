package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/TMHSDigital/subenum/internal/diff"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/mcp"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/validate"
	"github.com/TMHSDigital/subenum/internal/wordlist"
	"github.com/TMHSDigital/subenum/pkg/subenum"
)

// maxMCPDepth is the deepest recursion a call may ask for, and
// maxMCPExclude the most exclude patterns; max_queries bounds the work
// either way. maxMCPRate is the highest rate a lab_scan call may set.
const (
	maxMCPDepth   = 3
	maxMCPExclude = 1000
	maxMCPRate    = 1000
)

// schemaField is one key of a JSON object whose keys keep the order written.
type schemaField struct {
	key string
	val any
}

// schemaObject is a JSON object with ordered keys, for the tools' input
// schemas. Every key and value goes through encoding/json and the only bytes
// written by hand are braces, colons and commas, so no name, description or
// enum entry can break out of its string, whatever it contains.
type schemaObject []schemaField

// MarshalJSON writes the fields in order.
func (o schemaObject) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := json.Marshal(f.key)
		if err != nil {
			return nil, err
		}
		val, err := json.Marshal(f.val)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		b.Write(val)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// inputSchema is the JSON Schema of a tool's arguments: an object with these
// properties and no others.
func inputSchema(props schemaObject, required ...string) json.RawMessage {
	schema := schemaObject{{"type", "object"}, {"properties", props}}
	if len(required) > 0 {
		schema = append(schema, schemaField{"required", required})
	}
	schema = append(schema, schemaField{"additionalProperties", false})
	raw, _ := json.Marshal(schema) // strings, numbers and booleans only: cannot fail
	return raw
}

// wordsSchema is the words argument, with the tool's own description.
func wordsSchema(description string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": maxMCPWords, "description": description}
}

// offsetSchema is the offset argument (#313): with the report's next_offset
// it lets an agent work through a word list longer than max_queries, one
// call at a time, each within the operator's caps.
var offsetSchema = schemaField{"offset", map[string]any{"type": "integer", "minimum": 0, "description": "Skip this many candidates at the start of the word list (after dedupe); default 0. When max_queries leaves words untested the report gives next_offset: call again with the same words and that offset to test the following ones."}}

// remediationProps are the scan settings an agent can change after a verdict
// that is not complete (#269). None can raise the operator's caps.
var remediationProps = schemaObject{
	{"retry_inconclusive", map[string]any{"type": "boolean", "description": "At the end, look up once more every name that timed out, was refused or failed; an answer replaces the first outcome. Use it when failures degraded the verdict."}},
	{"auto_rate", map[string]any{"type": "boolean", "description": "Halve the query rate while many lookups fail and raise it again once they succeed, never above the starting rate, instead of giving up."}},
	{"exclude", map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": maxMCPExclude, "description": "Names out of scope that are never queried: one name (mail.example.com) or a branch (*.corp.example.com)."}},
	{"depth", map[string]any{"type": "integer", "minimum": 1, "maximum": maxMCPDepth, "description": "Enumerate the words again under every name found, down to this many levels; default 1, no recursion. Every level stays within max_queries."}},
}

// remediation holds the remediationProps arguments.
type remediation struct {
	RetryInconclusive bool     `json:"retry_inconclusive"`
	AutoRate          bool     `json:"auto_rate"`
	Exclude           []string `json:"exclude"`
	Depth             int      `json:"depth"`
}

// apply checks the arguments and sets them on cfg.
func (r remediation) apply(cfg *subenum.Config) error {
	if r.Depth < 0 || r.Depth > maxMCPDepth {
		return fmt.Errorf("depth must be 1 to %d, got %d", maxMCPDepth, r.Depth)
	}
	if len(r.Exclude) > maxMCPExclude {
		return fmt.Errorf("exclude has %d entries; at most %d", len(r.Exclude), maxMCPExclude)
	}
	cfg.RetryInconclusive, cfg.AutoRate, cfg.Exclude = r.RetryInconclusive, r.AutoRate, r.Exclude
	if r.Depth > 1 {
		cfg.Recursive, cfg.Depth = true, r.Depth
	}
	return nil
}

// recordTypeSchema offers every type -type accepts (#264).
var recordTypeSchema = map[string]any{
	"type":        "array",
	"items":       map[string]any{"enum": dns.Types()},
	"description": "Record types to look up; default A and AAAA. CNAME and NS add takeover hints.",
}

// labScanArgs are lab_scan's arguments. TestMCPInputSchemasMatchArgs keeps
// them and the tool's input schema in step.
type labScanArgs struct {
	Scenario   string   `json:"scenario"`
	Words      []string `json:"words"`
	Types      []string `json:"types"`
	Rate       int      `json:"rate"`
	MaxQueries int      `json:"max_queries"`
	Offset     int      `json:"offset"`
	Force      bool     `json:"force"`
	remediation
}

func labScanTool(cfg mcpConfig) mcp.Tool {
	schema := inputSchema(append(schemaObject{
		{"scenario", map[string]any{"enum": labScenarios(), "description": fmt.Sprintf("Lab scenario to scan; default lab1-first-scan. Each is a fictional zone for %s served on this machine.%s",
			labDomain, labScenarioGuide())}},
		{"words", wordsSchema("Subdomain labels to try; default the labs' short wordlist.")},
		{"types", recordTypeSchema},
		{"rate", map[string]any{"type": "integer", "minimum": 0, "maximum": maxMCPRate, "description": "Queries per second; 0 or absent is unlimited. Lab traffic stays on this machine."}},
		{"max_queries", map[string]any{"type": "integer", "minimum": 1, "maximum": cfg.maxQueries, "description": "Most names to test."}},
		offsetSchema,
		{"force", map[string]any{"type": "boolean", "description": "Scan a wildcard zone anyway, filtering answers that match the wildcard."}},
	}, remediationProps...))
	return mcp.Tool{
		Name:         "lab_scan",
		Title:        "Scan a lab zone",
		Description:  fmt.Sprintf("Enumerate subdomains of %s in one of subenum's lab scenarios: fictional zones answered by a DNS server on this machine, so no traffic leaves it. Safe for practice and for learning how wildcards, rate limits and failing resolvers change a scan's verdict.", labDomain),
		InputSchema:  schema,
		OutputSchema: mcpReportSchema,
		Annotations:  mcp.Annotations{ReadOnlyHint: true},
		Call: func(ctx context.Context, raw json.RawMessage) mcp.Result {
			var args labScanArgs
			if err := strictUnmarshal(raw, &args); err != nil {
				return mcp.Errorf("invalid arguments: %v", err)
			}
			if args.Scenario == "" {
				args.Scenario = "lab1-first-scan"
			}
			if !slices.Contains(labScenarios(), args.Scenario) {
				return mcp.Errorf("unknown scenario %q; choose one of %s", args.Scenario, strings.Join(labScenarios(), ", "))
			}
			if args.Rate < 0 || args.Rate > maxMCPRate {
				return mcp.Errorf("rate must be 0 to %d, got %d", maxMCPRate, args.Rate)
			}
			maxQueries, err := callBudget(cfg, args.MaxQueries)
			if err != nil {
				return mcp.Errorf("%v", err)
			}
			words, err := callWords(args.Words, labWords(), labDomain, args.Offset)
			if err != nil {
				return mcp.Errorf("%v", err)
			}
			scanCfg := subenum.Config{
				Domain: labDomain,
				Words:  words,
				// The server is in-process: allow for a busy machine, but
				// keep lab5's deliberate timeouts short.
				Timeout:     labTimeout,
				Attempts:    2,
				Types:       args.Types,
				Rate:        args.Rate,
				MaxQueries:  maxQueries,
				MaxDuration: cfg.maxDuration,
				Force:       args.Force,
			}
			if err := args.apply(&scanCfg); err != nil {
				return mcp.Errorf("%v", err)
			}
			srv, err := serveLab(args.Scenario) //nolint:contextcheck // the server lives until the deferred Close, not until ctx ends
			if err != nil {
				return mcp.Errorf("%v", err)
			}
			defer srv.Close()
			scanCfg.Resolver = srv.Addr
			report := runMCPScan(ctx, scanCfg, args.Offset)
			report.Scenario = args.Scenario
			return report.result()
		},
	}
}

// scanArgs are scan's arguments. TestMCPInputSchemasMatchArgs keeps them and
// the tool's input schema in step.
type scanArgs struct {
	Domain     string   `json:"domain"`
	Words      []string `json:"words"`
	Types      []string `json:"types"`
	MaxQueries int      `json:"max_queries"`
	Offset     int      `json:"offset"`
	Sources    []string `json:"sources"`
	remediation
}

func scanTool(cfg mcpConfig) mcp.Tool {
	props := schemaObject{
		{"domain", map[string]any{"type": "string", "description": fmt.Sprintf("Domain to enumerate: one of %s, or a subdomain of one.", strings.Join(cfg.allow, ", "))}},
		{"words", wordsSchema("Subdomain labels to try; default subenum's bundled list of the most common ones.")},
		{"types", recordTypeSchema},
		{"max_queries", map[string]any{"type": "integer", "minimum": 1, "maximum": cfg.maxQueries, "description": fmt.Sprintf("Most names to test; default and ceiling %d.", cfg.maxQueries)}},
		offsetSchema,
	}
	if len(cfg.sources) > 0 {
		props = append(props, schemaField{"sources", map[string]any{"type": "array", "items": map[string]any{"enum": cfg.sources}, "description": "Passive sources to seed candidates from before the scan; default none. Their names are added to words after dedupe, count against max_queries, and are each verified by a lookup. One HTTPS request per source."}})
	}
	schema := inputSchema(append(props, remediationProps...), "domain")
	var calls atomic.Int64 // scan calls this session has made
	return mcp.Tool{
		Name:  "scan",
		Title: "Enumerate subdomains",
		Description: fmt.Sprintf("Enumerate subdomains of a real domain by DNS, through the operator's resolver at %d queries per second, testing at most %d names in %s. Only domains the operator allowed can be scanned: %s.",
			cfg.rate, cfg.maxQueries, cfg.maxDuration, strings.Join(cfg.allow, ", ")),
		InputSchema:  schema,
		OutputSchema: mcpReportSchema,
		Annotations:  mcp.Annotations{ReadOnlyHint: true, OpenWorldHint: true},
		Call: func(ctx context.Context, raw json.RawMessage) mcp.Result {
			var args scanArgs
			if err := strictUnmarshal(raw, &args); err != nil {
				return mcp.Errorf("invalid arguments: %v", err)
			}
			var counted []*countedSource
			for _, name := range args.Sources {
				if !slices.Contains(cfg.sources, name) {
					if len(cfg.sources) == 0 {
						return mcp.Errorf("sources are off: the operator did not enable any with -sources")
					}
					return mcp.Errorf("source %q is not enabled; choose from %s", name, strings.Join(cfg.sources, ", "))
				}
				if !slices.ContainsFunc(counted, func(c *countedSource) bool { return c.name == name }) {
					counted = append(counted, &countedSource{name: name, src: mcpSources[name]()})
				}
			}
			domain, _, err := validate.NormalizeDomain(args.Domain)
			if err != nil {
				return mcp.Errorf("domain: %v", err)
			}
			if !allowed(cfg.allow, domain) {
				return mcp.Errorf("refused: %s is not in the operator's allow-list (%s). Ask the operator to add it to -allow if you have permission to test it.",
					domain, strings.Join(cfg.allow, ", "))
			}
			maxQueries, err := callBudget(cfg, args.MaxQueries)
			if err != nil {
				return mcp.Errorf("%v", err)
			}
			words, err := callWords(args.Words, nil, domain, args.Offset)
			if err != nil {
				return mcp.Errorf("%v", err)
			}
			var sources []subenum.Source
			for _, c := range counted {
				sources = append(sources, c)
			}
			scanCfg := subenum.Config{
				Domain:      domain,
				Words:       words,
				Resolver:    cfg.dnsServer,
				Timeout:     cfg.timeout,
				Types:       args.Types,
				Rate:        cfg.rate,
				MaxQueries:  maxQueries,
				MaxDuration: cfg.maxDuration,
				Sources:     sources,
			}
			if err := args.apply(&scanCfg); err != nil {
				return mcp.Errorf("%v", err)
			}
			if calls.Add(1) > int64(cfg.maxCalls) {
				return mcp.Errorf("session budget spent: the operator allows %d scan calls per session (-max-calls)", cfg.maxCalls)
			}
			report := runMCPScan(ctx, scanCfg, args.Offset)
			for _, c := range counted {
				s := mcpSource{Name: c.name, Names: c.names}
				var tr *passive.Truncated
				switch {
				case errors.As(c.err, &tr):
					s.Truncated = true // names used, but some may be missing (#272)
				case c.err != nil:
					s.Error = c.err.Error()
				}
				report.Sources = append(report.Sources, s)
			}
			return report.result()
		},
	}
}

// allowed reports whether domain is an allow-listed apex or under one.
func allowed(allow []string, domain string) bool {
	for _, apex := range allow {
		if domain == apex || strings.HasSuffix(domain, "."+apex) {
			return true
		}
	}
	return false
}

// callBudget is the max_queries a call gets: the operator's cap unless the
// call asks for less.
func callBudget(cfg mcpConfig, asked int) (int, error) {
	switch {
	case asked < 0:
		return 0, fmt.Errorf("max_queries must be at least 1, got %d", asked)
	case asked > cfg.maxQueries:
		return 0, fmt.Errorf("max_queries %d is above the operator's cap of %d", asked, cfg.maxQueries)
	case asked == 0:
		return cfg.maxQueries, nil
	}
	return asked, nil
}

// callWords is the word list a call scans: its words, or fallback (nil is
// the bundled list) without any, as a scan of domain builds it (valid
// labels, deduplicated, in order) and without its first offset candidates,
// so a call can go on where max_queries stopped an earlier one (#313).
func callWords(words, fallback []string, domain string, offset int) ([]string, error) {
	if len(words) > maxMCPWords {
		return nil, fmt.Errorf("words has %d entries; at most %d", len(words), maxMCPWords)
	}
	if offset < 0 {
		return nil, fmt.Errorf("offset must be 0 or more, got %d", offset)
	}
	if words == nil {
		words = fallback
	}
	if words == nil {
		words = subenum.DefaultWords()
	}
	entries, _, _ := wordlist.Build(words, domain)
	switch {
	case offset == 0 && len(entries) == 0:
		return words, nil // the scan says why it cannot start
	case offset >= len(entries):
		return nil, fmt.Errorf("offset %d is past the end of the word list, which has %d candidates", offset, len(entries))
	}
	return entries[offset:], nil
}

// nextOffset is the offset of the first candidate a scan left untested
// because max_queries was reached, for a call that continues it, or 0 when
// there is nothing to continue from: no candidate was skipped, the words
// were all tested (the skipped ones came from recursion or a source), or
// the scan stopped for another reason (the time budget, an abort, a
// cancellation), which leaves gaps among the names it tested. offset is the
// one the scan itself started at.
func nextOffset(cfg subenum.Config, stats subenum.Stats, offset int) int {
	if stats.Skipped == 0 || cfg.MaxQueries == 0 || stats.Total() != int64(cfg.MaxQueries) {
		return 0
	}
	// Candidates are admitted in order, the words before anything else, so
	// the names tested are the first MaxQueries the exclusions let through.
	if len(cfg.Exclude) == 0 {
		if cfg.MaxQueries < len(cfg.Words) {
			return offset + cfg.MaxQueries
		}
		return 0
	}
	tested := 0
	excluded := scan.Excluder(cfg.Exclude)
	for i, word := range cfg.Words {
		if excluded(word + "." + cfg.Domain) {
			continue
		}
		if tested == cfg.MaxQueries {
			return offset + i
		}
		tested++
	}
	return 0
}

// strictUnmarshal decodes tool arguments, rejecting unknown ones so a
// misspelled or invented setting (a resolver, say) fails loudly instead of
// being ignored.
func strictUnmarshal(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// explainStatsArgs are explain_stats's arguments.
// TestMCPInputSchemasMatchArgs keeps them and the tool's input schema in
// step.
type explainStatsArgs struct {
	Stats string `json:"stats"`
}

func explainStatsTool() mcp.Tool {
	return mcp.Tool{
		Name:        "explain_stats",
		Title:       "Explain a run-quality report",
		Description: "Explain in plain language a run-quality report written by the subenum command line with -stats (or the last line of -format jsonl output): how far the results can be trusted, why, and what to change next time. Pass the file's contents, not its path.",
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "stats": {"type": "string", "description": "The JSON contents of a -stats file, or jsonl output ending in its summary line."}
  },
  "required": ["stats"],
  "additionalProperties": false
}`),
		Annotations: mcp.Annotations{ReadOnlyHint: true},
		Call: func(_ context.Context, raw json.RawMessage) mcp.Result {
			var args explainStatsArgs
			if err := strictUnmarshal(raw, &args); err != nil {
				return mcp.Errorf("invalid arguments: %v", err)
			}
			s, err := parseSummary(args.Stats)
			if err != nil {
				return mcp.Errorf("%v", err)
			}
			return mcp.Result{Text: explainSummary(s)}
		},
	}
}

// diffArgs are diff's arguments. TestMCPInputSchemasMatchArgs keeps them and
// the tool's input schema in step.
type diffArgs struct {
	Previous string   `json:"previous"`
	Current  string   `json:"current"`
	Types    []string `json:"types"`
}

// diffTool compares two result sets as `subenum diff -records` does (#333),
// without a DNS query. Like explain_stats it takes contents, not paths, and
// the transport's message limit bounds them.
func diffTool() mcp.Tool {
	results := "a scan or lab_scan report (or its results array), or the contents of a subenum results file in any format (json, jsonl, csv or text)"
	return mcp.Tool{
		Name:        "diff",
		Title:       "Compare two result sets",
		Description: "Compare two subenum result sets without sending a DNS query: names added, names missing, and names whose records changed. Address changes behind a CNAME are not counted, so CDN rotation is not reported as a change. Pass contents, not paths.",
		InputSchema: inputSchema(schemaObject{
			{"previous", map[string]any{"type": "string", "description": "The earlier results: " + results + "."}},
			{"current", map[string]any{"type": "string", "description": "The later results: " + results + "."}},
			{"types", map[string]any{"type": "array", "items": map[string]any{"enum": dns.Types()}, "description": "Record types to compare for changed names; default every type."}},
		}, "previous", "current"),
		OutputSchema: mcpDiffSchema,
		Annotations:  mcp.Annotations{ReadOnlyHint: true},
		Call: func(_ context.Context, raw json.RawMessage) mcp.Result {
			var args diffArgs
			if err := strictUnmarshal(raw, &args); err != nil {
				return mcp.Errorf("invalid arguments: %v", err)
			}
			var types []string // every type
			if len(args.Types) > 0 {
				var err error
				if types, err = dns.ParseTypes(strings.Join(args.Types, ",")); err != nil {
					return mcp.Errorf("types: %v", err)
				}
			}
			prev, err := parseMCPResults(args.Previous)
			if err != nil {
				return mcp.Errorf("previous: %v", err)
			}
			cur, err := parseMCPResults(args.Current)
			if err != nil {
				return mcp.Errorf("current: %v", err)
			}
			return mcpDiff(prev, cur, types).result()
		},
	}
}

// parseMCPResults reads a result set for diff: a scan or lab_scan report, its
// results array, or a results file in any output format.
func parseMCPResults(text string) (baseline, error) {
	trimmed := []byte(strings.TrimSpace(strings.TrimPrefix(text, string(rune(0xFEFF)))))
	var raw json.RawMessage
	switch {
	case bytes.HasPrefix(trimmed, []byte("{")):
		var report map[string]json.RawMessage
		if json.Unmarshal(trimmed, &report) == nil {
			raw = report["results"]
		}
	case bytes.HasPrefix(trimmed, []byte("[")):
		// A report's results have "name"; a -format json file's "subdomain".
		var items []map[string]json.RawMessage
		if json.Unmarshal(trimmed, &items) == nil && len(items) > 0 {
			if _, ok := items[0]["name"]; ok {
				raw = trimmed
			}
		}
	}
	if raw == nil {
		return parseBaseline(trimmed)
	}
	var results []mcpResult
	if err := json.Unmarshal(raw, &results); err != nil {
		return baseline{}, fmt.Errorf("reading the report's results: %w", err)
	}
	b := baseline{names: map[string]struct{}{}, records: map[string][]dns.Record{}, hasRecords: true}
	for _, r := range results {
		name := diff.Name(r.Name)
		if name == "" {
			continue
		}
		b.names[name] = struct{}{}
		for _, rec := range r.Records {
			if typ, value, ok := strings.Cut(rec, " "); ok {
				b.records[name] = append(b.records[name], dns.Record{Type: typ, Value: value})
			}
		}
	}
	return b, nil
}
