package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"github.com/TMHSDigital/subenum/internal/labzone"
	"github.com/TMHSDigital/subenum/internal/mcp"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/validate"
	"github.com/TMHSDigital/subenum/internal/wordlist"
	"github.com/TMHSDigital/subenum/pkg/subenum"
)

// `subenum mcp` serves subdomain enumeration to AI agents over the Model
// Context Protocol (#131). The operator decides everything that matters for
// safety on the command line: which domains a live scan may target, the
// resolver, the query rate and the budgets. The model can ask for a smaller
// budget, never a larger one, and never picks a resolver.

// The lab scenarios and their wordlist are compiled in, so lab_scan works
// from any directory and sends nothing off the machine.
//
//go:embed examples/labs/*.zone examples/labs/words.txt
var labFiles embed.FS

const (
	labDir    = "examples/labs"
	labDomain = "lab.example" // the apex every lab scenario answers for

	defaultMCPMaxQueries  = 1000
	defaultMCPRate        = 20
	defaultMCPMaxDuration = 2 * time.Minute

	maxMCPWords = 50000 // entries a words argument may hold
	labTimeout  = 2 * time.Second

	verdictNotRun = "not_run" // the scan stopped before testing any name
)

// mcpConfig is the operator's side of the server.
type mcpConfig struct {
	allow       []string // apexes a live scan may target, normalized
	dnsServer   string
	maxQueries  int
	rate        int
	maxDuration time.Duration
	timeout     time.Duration // one lookup, live scans
	sources     []string      // passive sources a scan call may ask for (#268)
	maxCalls    int           // scan calls one session may make (#240)
}

// defaultMCPMaxCalls bounds a session's scan calls, so an agent that loops
// (or keeps working after its user left) cannot multiply -max-queries
// without end.
const defaultMCPMaxCalls = 100

// mcpSources builds the passive sources -sources may enable, by name. Tests
// replace it so no request leaves the machine.
var mcpSources = map[string]func() subenum.Source{
	"ct":      subenum.CertificateTransparency,
	"wayback": subenum.WaybackMachine,
}

// mcpSourceNames lists mcpSources' keys in a fixed order.
func mcpSourceNames() []string {
	names := make([]string, 0, len(mcpSources))
	for name := range mcpSources {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// countedSource remembers what its source returned, for the report.
type countedSource struct {
	name  string
	src   subenum.Source
	names int
	err   error
}

func (c *countedSource) Names(ctx context.Context, domain string) ([]string, error) {
	names, err := c.src.Names(ctx, domain)
	c.names, c.err = len(names), err
	return names, err
}

// runMCP runs `subenum mcp [flags]` until standard input closes or a
// signal arrives.
func runMCP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, code, ok := parseMCPFlags(args, stderr)
	if !ok {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := mcpServer(cfg)
	if err := srv.Serve(ctx, stdin, stdout); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitFailure
	}
	return exitOK
}

func parseMCPFlags(args []string, stderr io.Writer) (cfg mcpConfig, code int, ok bool) {
	fs := flag.NewFlagSet(ProgramName+" mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var allow, sources string
	var timeoutMs int
	fs.StringVar(&allow, "allow", "", "Comma-separated domains the scan tool may enumerate, each with its subdomains. Without it only lab_scan and explain_stats are offered")
	fs.StringVar(&cfg.dnsServer, "dns-server", DefaultDNSServer, "Resolver for live scans: ip:port, tls://host or https://host/path")
	fs.IntVar(&cfg.maxQueries, "max-queries", defaultMCPMaxQueries, "Most candidate names one tool call may test; a call can ask for fewer")
	fs.IntVar(&cfg.rate, "rate", defaultMCPRate, "DNS queries per second for live scans")
	fs.DurationVar(&cfg.maxDuration, "max-duration", defaultMCPMaxDuration, "Longest one tool call may scan")
	fs.IntVar(&timeoutMs, "timeout", int(subenum.DefaultTimeout/time.Millisecond), "Live-scan DNS lookup timeout in milliseconds")
	fs.IntVar(&cfg.maxCalls, "max-calls", defaultMCPMaxCalls, "Most scan calls one session may make; with -max-queries it caps the session's live lookups")
	fs.StringVar(&sources, "sources", "", "Comma-separated passive sources ("+strings.Join(mcpSourceNames(), ", ")+") a scan call may ask for. Off by default: they send the domain to third parties")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "Usage: %s mcp [flags]\n\n", ProgramName)
		_, _ = fmt.Fprintln(stderr, "Serves subenum to AI agents over the Model Context Protocol (stdio).")
		_, _ = fmt.Fprintln(stderr, "Tools: lab_scan (local lab zones only), scan (domains in -allow only), explain_stats.")
		_, _ = fmt.Fprintln(stderr, "Only allow domains you own or have permission to test.")
		_, _ = fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cfg, exitOK, false
		}
		return cfg, exitUsage, false
	}
	fail := func(format string, a ...any) (mcpConfig, int, bool) {
		_, _ = fmt.Fprintf(stderr, "Error: "+format+"\n", a...)
		return cfg, exitUsage, false
	}
	if fs.NArg() > 0 {
		return fail("unexpected argument %q; the scan target comes from the client, within -allow", fs.Arg(0))
	}
	// Caps are mandatory: 0 means unlimited elsewhere, which an unattended
	// agent must never get.
	if cfg.maxQueries < 1 {
		return fail("-max-queries must be at least 1, got %d", cfg.maxQueries)
	}
	if cfg.rate < 1 {
		return fail("-rate must be at least 1, got %d", cfg.rate)
	}
	if cfg.maxDuration <= 0 {
		return fail("-max-duration must be positive, got %s", cfg.maxDuration)
	}
	if timeoutMs < 1 {
		return fail("-timeout must be at least 1 millisecond, got %d", timeoutMs)
	}
	if cfg.maxCalls < 1 {
		return fail("-max-calls must be at least 1, got %d", cfg.maxCalls)
	}
	cfg.timeout = time.Duration(timeoutMs) * time.Millisecond
	if err := validate.DNSServer(cfg.dnsServer); err != nil {
		return fail("-dns-server: %v", err)
	}
	for entry := range strings.SplitSeq(allow, ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		domain, _, err := validate.NormalizeDomain(entry)
		if err != nil {
			return fail("-allow %q: %v", entry, err)
		}
		if !slices.Contains(cfg.allow, domain) {
			cfg.allow = append(cfg.allow, domain)
		}
	}
	for name := range strings.SplitSeq(sources, ",") {
		if name = strings.ToLower(strings.TrimSpace(name)); name == "" {
			continue
		}
		if _, ok := mcpSources[name]; !ok {
			return fail("-sources: unknown source %q; choose from %s", name, strings.Join(mcpSourceNames(), ", "))
		}
		if !slices.Contains(cfg.sources, name) {
			cfg.sources = append(cfg.sources, name)
		}
	}
	return cfg, exitOK, true
}

func mcpServer(cfg mcpConfig) *mcp.Server {
	tools := []mcp.Tool{labScanTool(cfg)}
	instructions := "subenum enumerates subdomains by DNS. lab_scan practises on local fictional zones and is always safe. "
	if len(cfg.allow) > 0 {
		tools = append(tools, scanTool(cfg))
		instructions += fmt.Sprintf("scan enumerates real domains, only under %s, with at most %d names per call at %d queries per second. ",
			strings.Join(cfg.allow, ", "), cfg.maxQueries, cfg.rate)
		if len(cfg.sources) > 0 {
			instructions += fmt.Sprintf("scan can also seed candidates from passive sources (%s) when a call lists them in sources. ",
				strings.Join(cfg.sources, ", "))
		}
	} else {
		instructions += "Live scanning is off: the operator allowed no domains. "
	}
	instructions += "Every scan returns a verdict: when it is not \"complete\", a name missing from the results may still exist. " +
		"explain_stats explains a run-quality report from the subenum command line (-stats)."
	tools = append(tools, explainStatsTool())
	return &mcp.Server{Name: ProgramName, Version: resolveVersion(), Instructions: instructions, Tools: tools}
}

// labScenarios lists the compiled-in scenarios by name, such as
// "lab1-first-scan".
func labScenarios() []string {
	entries, _ := labFiles.ReadDir(labDir)
	var names []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".zone"); ok {
			names = append(names, name)
		}
	}
	return names
}

// labScenarioDescription is what a scenario teaches, from its file's opening
// comment (#275): the comment lines before the first record, without the
// "Lab N:" prefix, the "Run:" hint or the indented command under it.
func labScenarioDescription(name string) string {
	b, _ := labFiles.ReadFile(path.Join(labDir, name+".zone"))
	var parts []string
	for line := range strings.Lines(string(b)) {
		text, ok := strings.CutPrefix(line, "#")
		if !ok {
			break
		}
		if strings.HasPrefix(text, "  ") { // a command to run
			continue
		}
		text = strings.TrimSpace(text)
		if strings.HasPrefix(text, "Lab ") {
			if _, rest, ok := strings.Cut(text, ": "); ok {
				text = rest
			}
		}
		text = strings.TrimSpace(strings.TrimSuffix(text, "Run:"))
		if text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, " ")
}

// labScenarioGuide lists every scenario with its description, for the
// lab_scan schema.
func labScenarioGuide() string {
	var b strings.Builder
	for _, name := range labScenarios() {
		if desc := labScenarioDescription(name); desc != "" {
			fmt.Fprintf(&b, " %s: %s", name, desc)
		}
	}
	return b.String()
}

func labWords() []string {
	b, _ := labFiles.ReadFile(path.Join(labDir, "words.txt"))
	words, _ := wordlist.ReadLinesFrom(bytes.NewReader(b))
	return words
}

// serveLab answers for lab.example from a compiled-in scenario on a
// loopback DNS server, as -simulate-zone does.
func serveLab(scenario string) (*dnsserver.Server, error) {
	b, err := labFiles.ReadFile(path.Join(labDir, scenario+".zone"))
	if err != nil {
		return nil, err
	}
	zone, err := labzone.Parse(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", scenario, err)
	}
	srv, err := dnsserver.Listen(dnsserver.Options{}, zone.Handler([]string{labDomain}))
	if err != nil {
		return nil, fmt.Errorf("starting the local DNS server: %w", err)
	}
	return srv, nil
}

// maxMCPDepth is the deepest recursion a call may ask for, and
// maxMCPExclude the most exclude patterns; max_queries bounds the work
// either way.
const (
	maxMCPDepth   = 3
	maxMCPExclude = 1000
)

// remediationProps are the scan settings an agent can change after a verdict
// that is not complete (#269). None can raise the operator's caps.
var remediationProps = fmt.Sprintf(`,
    "retry_inconclusive": {"type": "boolean", "description": "At the end, look up once more every name that timed out, was refused or failed; an answer replaces the first outcome. Use it when failures degraded the verdict."},
    "auto_rate": {"type": "boolean", "description": "Halve the query rate while many lookups fail and raise it again once they succeed, never above the starting rate, instead of giving up."},
    "exclude": {"type": "array", "items": {"type": "string"}, "maxItems": %d, "description": "Names out of scope that are never queried: one name (mail.example.com) or a branch (*.corp.example.com)."},
    "depth": {"type": "integer", "minimum": 1, "maximum": %d, "description": "Enumerate the words again under every name found, down to this many levels; default 1, no recursion. Every level stays within max_queries."}`,
	maxMCPExclude, maxMCPDepth)

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
var recordTypeSchema = func() json.RawMessage {
	enum, _ := json.Marshal(dns.Types())
	return json.RawMessage(`{"type": "array", "items": {"enum": ` + string(enum) + `}, "description": "Record types to look up; default A and AAAA. CNAME and NS add takeover hints."}`)
}()

func labScanTool(cfg mcpConfig) mcp.Tool {
	scenarios, _ := json.Marshal(labScenarios())
	scenarioDesc, _ := json.Marshal(fmt.Sprintf("Lab scenario to scan; default lab1-first-scan. Each is a fictional zone for %s served on this machine.%s",
		labDomain, labScenarioGuide()))
	schema := fmt.Sprintf(`{
  "type": "object",
  "properties": {
    "scenario": {"enum": %s, "description": %s},
    "words": {"type": "array", "items": {"type": "string"}, "maxItems": %d, "description": "Subdomain labels to try; default the labs' short wordlist."},
    "types": %s,
    "rate": {"type": "integer", "minimum": 0, "maximum": 1000, "description": "Queries per second; 0 or absent is unlimited. Lab traffic stays on this machine."},
    "max_queries": {"type": "integer", "minimum": 1, "maximum": %d, "description": "Most names to test."},
    "force": {"type": "boolean", "description": "Scan a wildcard zone anyway, filtering answers that match the wildcard."}%s
  },
  "additionalProperties": false
}`, scenarios, scenarioDesc, maxMCPWords, recordTypeSchema, cfg.maxQueries, remediationProps)
	return mcp.Tool{
		Name:         "lab_scan",
		Title:        "Scan a lab zone",
		Description:  fmt.Sprintf("Enumerate subdomains of %s in one of subenum's lab scenarios: fictional zones answered by a DNS server on this machine, so no traffic leaves it. Safe for practice and for learning how wildcards, rate limits and failing resolvers change a scan's verdict.", labDomain),
		InputSchema:  json.RawMessage(schema),
		OutputSchema: mcpReportSchema,
		Annotations:  mcp.Annotations{ReadOnlyHint: true},
		Call: func(ctx context.Context, raw json.RawMessage) mcp.Result {
			var args struct {
				Scenario   string   `json:"scenario"`
				Words      []string `json:"words"`
				Types      []string `json:"types"`
				Rate       int      `json:"rate"`
				MaxQueries int      `json:"max_queries"`
				Force      bool     `json:"force"`
				remediation
			}
			if err := strictUnmarshal(raw, &args); err != nil {
				return mcp.Errorf("invalid arguments: %v", err)
			}
			if args.Scenario == "" {
				args.Scenario = "lab1-first-scan"
			}
			if !slices.Contains(labScenarios(), args.Scenario) {
				return mcp.Errorf("unknown scenario %q; choose one of %s", args.Scenario, strings.Join(labScenarios(), ", "))
			}
			if args.Rate < 0 || args.Rate > 1000 {
				return mcp.Errorf("rate must be 0 to 1000, got %d", args.Rate)
			}
			maxQueries, err := callBudget(cfg, args.MaxQueries)
			if err != nil {
				return mcp.Errorf("%v", err)
			}
			words, err := callWords(args.Words, labWords())
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
			report := runMCPScan(ctx, scanCfg)
			report.Scenario = args.Scenario
			return report.result()
		},
	}
}

func scanTool(cfg mcpConfig) mcp.Tool {
	sourcesProp := ""
	if len(cfg.sources) > 0 {
		enum, _ := json.Marshal(cfg.sources)
		sourcesProp = fmt.Sprintf(`,
    "sources": {"type": "array", "items": {"enum": %s}, "description": "Passive sources to seed candidates from before the scan; default none. Their names are added to words after dedupe, count against max_queries, and are each verified by a lookup. One HTTPS request per source."}`, enum)
	}
	schema := fmt.Sprintf(`{
  "type": "object",
  "properties": {
    "domain": {"type": "string", "description": "Domain to enumerate: one of %s, or a subdomain of one."},
    "words": {"type": "array", "items": {"type": "string"}, "maxItems": %d, "description": "Subdomain labels to try; default subenum's bundled list of the most common ones."},
    "types": %s,
    "max_queries": {"type": "integer", "minimum": 1, "maximum": %d, "description": "Most names to test; default and ceiling %d."}%s%s
  },
  "required": ["domain"],
  "additionalProperties": false
}`, strings.Join(cfg.allow, ", "), maxMCPWords, recordTypeSchema, cfg.maxQueries, cfg.maxQueries, sourcesProp, remediationProps)
	var calls atomic.Int64 // scan calls this session has made
	return mcp.Tool{
		Name:  "scan",
		Title: "Enumerate subdomains",
		Description: fmt.Sprintf("Enumerate subdomains of a real domain by DNS, through the operator's resolver at %d queries per second, testing at most %d names in %s. Only domains the operator allowed can be scanned: %s.",
			cfg.rate, cfg.maxQueries, cfg.maxDuration, strings.Join(cfg.allow, ", ")),
		InputSchema:  json.RawMessage(schema),
		OutputSchema: mcpReportSchema,
		Annotations:  mcp.Annotations{ReadOnlyHint: true, OpenWorldHint: true},
		Call: func(ctx context.Context, raw json.RawMessage) mcp.Result {
			var args struct {
				Domain     string   `json:"domain"`
				Words      []string `json:"words"`
				Types      []string `json:"types"`
				MaxQueries int      `json:"max_queries"`
				Sources    []string `json:"sources"`
				remediation
			}
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
			words, err := callWords(args.Words, nil)
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
			report := runMCPScan(ctx, scanCfg)
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

func callWords(words, fallback []string) ([]string, error) {
	if len(words) > maxMCPWords {
		return nil, fmt.Errorf("words has %d entries; at most %d", len(words), maxMCPWords)
	}
	if words == nil {
		return fallback, nil
	}
	return words, nil
}

// strictUnmarshal decodes tool arguments, rejecting unknown ones so a
// misspelled or invented setting (a resolver, say) fails loudly instead of
// being ignored.
func strictUnmarshal(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

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

func runMCPScan(ctx context.Context, cfg subenum.Config) *mcpReport {
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
			if report.Error == "" {
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
			var args struct {
				Stats string `json:"stats"`
			}
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

// parseSummary reads a -stats file, or finds the summary line at the end
// of jsonl output.
func parseSummary(text string) (output.Summary, error) {
	var s output.Summary
	if json.Unmarshal([]byte(text), &s) == nil && s.Type == "summary" {
		return s, nil
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		s = output.Summary{}
		if json.Unmarshal([]byte(strings.TrimSpace(lines[i])), &s) == nil && s.Type == "summary" {
			return s, nil
		}
	}
	return s, errors.New(`stats is not a subenum run-quality report: expected JSON with "type": "summary", as -stats writes`)
}

// verdictMeaning says what each verdict lets the reader conclude.
var verdictMeaning = map[string]string{
	scan.VerdictComplete:   "the results can be trusted, and a name missing from them most likely does not exist",
	scan.VerdictDegraded:   "the results are usable, but some names were not tested or got no answer, so a missing name may still exist",
	scan.VerdictUnreliable: "too many lookups failed: a missing name means nothing, and the scan should be repeated",
}

func explainSummary(s output.Summary) string {
	var b strings.Builder
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(&b, format+"\n", a...) }
	p("Overall verdict: %s (%s).", s.Verdict, s.Reason)
	if m := verdictMeaning[s.Verdict]; m != "" {
		p("That means %s.", m)
	}
	switch {
	case s.Simulated:
		p("This was a simulated run (-simulate): the results are invented and no DNS query was sent.")
	case s.Zone != "":
		p("This was a lab run: answers came from the scenario %s on a local DNS server.", s.Zone)
	}
	if !s.Simulated {
		rate := "no rate limit"
		if s.RateLimit > 0 {
			rate = fmt.Sprintf("a limit of %d per second", s.RateLimit)
		}
		p("%d DNS queries went to %s in %.1fs, %.0f per second against %s.", s.QueriesSent, s.Resolver, float64(s.DurationMs)/1000, s.AchievedQPS, rate)
	}
	for _, t := range s.Targets {
		p("")
		explainTarget(p, t)
	}
	if s.Diff != nil {
		p("")
		p("Compared with %s: %d added, %d removed, %d changed.", s.Diff.Previous, s.Diff.Added, s.Diff.Removed, s.Diff.Changed)
		if s.Diff.Unverified > 0 {
			p("%d earlier names could not be checked, so they are not counted as removed.", s.Diff.Unverified)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func explainTarget(p func(string, ...any), t output.TargetSummary) {
	o := t.Outcomes
	p("%s: %s, verdict %s (%s).", t.Domain, t.Status, t.Verdict, t.Reason)
	if t.Error != "" {
		p("  Error: %s", t.Error)
	}
	p("  %d of %d candidate names tested, %d found. Outcomes: %d resolved, %d do not exist, %d timed out, %d refused, %d other failures, %d matched the wildcard.",
		t.Processed, t.Total, t.Found, o.Resolved, o.NXDomain, o.Timeout, o.Refused, o.Other, o.WildcardFiltered)
	failed := o.Timeout + o.Refused + o.Other
	switch {
	case t.Verdict == scan.VerdictUnreliable:
		p("  Next time: lower -rate or add -auto-rate, try another -dns-server, and rerun; -retry-inconclusive retries the %d names without an answer.", failed)
	case failed > 0:
		p("  %d names got no answer; -retry-inconclusive looks them up again at the end of the scan.", failed)
	}
	if t.SkippedCap > 0 {
		budget := "-max-queries"
		if t.StoppedBy == "duration" {
			budget = "-max-duration"
		}
		p("  %d names were not tested because %s ran out; raise it, or continue with -resume.", t.SkippedCap, budget)
	}
	if t.Wildcard {
		p("  The domain answers every name (a wildcard), so subenum dropped %d answers matching the wildcard; a real name that answers the same way is dropped too.", o.WildcardFiltered)
	}
	if t.Takeover > 0 {
		p("  %d results have a subdomain-takeover hint: leads to verify by hand, not findings.", t.Takeover)
	}
	if t.Internal > 0 {
		p("  %d public names answer with internal (private, loopback or similar) addresses.", t.Internal)
	}
	if len(t.AXFRAllowed) > 0 {
		p("  Zone transfer (AXFR) was allowed by %s: anyone can list the zone, a misconfiguration to fix.", strings.Join(t.AXFRAllowed, ", "))
	}
	if t.ZoneDenial == "nsec" {
		p("  The zone is signed with plain NSEC, so every name in it can be listed by walking the chain.")
	}
	for _, src := range t.Sources {
		if src.Error != "" {
			p("  Passive source %s failed (%s); the scan went on without it.", src.Name, src.Error)
		}
		if src.Truncated {
			p("  Passive source %s stopped at one of its limits: its %d names were scanned, but some hosts may be missing.", src.Name, src.Names)
		}
	}
	if t.Permutation != nil {
		p("  Permutation pass: %d candidates from %d seeds, %d found.", t.Permutation.Candidates, t.Permutation.Seeds, t.Permutation.Found)
	}
}
