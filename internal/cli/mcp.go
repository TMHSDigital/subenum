package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/TMHSDigital/subenum/examples/labs"
	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"github.com/TMHSDigital/subenum/internal/labzone"
	"github.com/TMHSDigital/subenum/internal/mcp"
	"github.com/TMHSDigital/subenum/internal/validate"
	"github.com/TMHSDigital/subenum/internal/wordlist"
	"github.com/TMHSDigital/subenum/pkg/subenum"
)

// `subenum mcp` serves subdomain enumeration to AI agents over the Model
// Context Protocol (#131). The operator decides everything that matters for
// safety on the command line: which domains a live scan may target, the
// resolver, the query rate and the budgets. The model can ask for a smaller
// budget, never a larger one, and never picks a resolver.

// The lab scenarios and their wordlist are compiled in (examples/labs), so
// lab_scan works from any directory and sends nothing off the machine.
var labFiles = labs.Files

const (
	labDir    = "."           // the scenarios sit at the root of labs.Files
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
