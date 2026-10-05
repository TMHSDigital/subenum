// subenum - A Go-based CLI tool for subdomain enumeration.
// Copyright (C) 2026 TM Hospitality Strategies
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// For authorized use only. Only scan domains you own or have explicit
// written permission to test.

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/tui"
	"github.com/TMHSDigital/subenum/internal/validate"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

const (
	ProgramName      = "subenum"
	DefaultDNSServer = "8.8.8.8:53"

	// highConcurrency is the -t above which the CLI warns (#58).
	highConcurrency = 10000
)

// Exit codes, documented in the README and in -h (#82). A signal exits with
// the shell convention 128+signum: 130 for SIGINT, 143 for SIGTERM.
const (
	exitOK      = 0
	exitFailure = 1 // a scan, the wordlist, the domain list or the output file failed
	exitUsage   = 2 // invalid flags or arguments
	exitPartial = 3 // -dL: some targets failed while others completed
)

const exitCodesHelp = `Exit codes:
  0    success
  1    a scan, the wordlist, the domain list or the output file failed
  2    invalid flags or arguments
  3    -dL: some targets failed while others completed
  130  interrupted (SIGINT, Ctrl+C); partial results are kept
  143  terminated (SIGTERM); partial results are kept
`

// signalReady, when set by a test, is closed once run's signal handler is
// installed.
var signalReady chan struct{}

// Version is the release identifier. Makefile, CI and the Dockerfile set it
// with -ldflags "-X main.Version=$(git describe --tags --dirty)". When it is
// empty (go install, plain go build), the module version from the build info
// is used, so there is no hand-maintained copy to drift between releases.
var Version = ""

// resolveVersion returns Version, else the main module version recorded by
// go install (for example v0.7.0), else "dev".
func resolveVersion() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// formatVersion trims a leading "v" so a tag like v0.7.0 does not print as vv0.7.0.
func formatVersion() string {
	v := resolveVersion()
	if v == "dev" {
		return ProgramName + " dev"
	}
	return ProgramName + " v" + strings.TrimPrefix(v, "v")
}

func main() {
	os.Exit(run())
}

// cliFlags holds all parsed command-line flag values.
type cliFlags struct {
	tui          bool
	wordlistFile string
	domainList   string
	concurrency  int
	timeoutMs    int
	dnsServer    string
	verbose      bool
	showVersion  bool
	showProgress bool
	testMode     bool
	testHitRate  int
	seed         uint64
	outputFile   string
	attempts     int
	retries      int
	force        bool
	format       string
	showRecords  bool
	rate         int
	recordTypes  string
	recursive    bool
	depth        int
	noAbort      bool
	maxQueries   int
}

// parseFlags parses args (without the program name). Flags may appear before or
// after the domain; the returned positionals are every non-flag argument.
func parseFlags(args []string) (cliFlags, []string, *flag.FlagSet, error) {
	var f cliFlags
	fs := flag.NewFlagSet(ProgramName, flag.ContinueOnError)
	fs.BoolVar(&f.tui, "tui", false, "Launch the interactive terminal UI (all other flags are ignored)")
	fs.StringVar(&f.wordlistFile, "w", "", "Path to the wordlist file (- for stdin)")
	fs.StringVar(&f.domainList, "dL", "", "File of apex domains to scan, one per line (- for stdin); replaces the <domain> argument")
	fs.IntVar(&f.concurrency, "t", 100, "Number of concurrent workers")
	fs.IntVar(&f.timeoutMs, "timeout", 1000, "DNS lookup timeout in milliseconds")
	fs.StringVar(&f.dnsServer, "dns-server", DefaultDNSServer, "DNS server to use (format: ip:port)")
	fs.BoolVar(&f.verbose, "v", false, "Enable verbose output")
	fs.BoolVar(&f.showVersion, "version", false, "Show version information")
	fs.BoolVar(&f.showProgress, "progress", true, "Show progress during scanning")
	fs.BoolVar(&f.testMode, "simulate", false, "Run in simulation mode without actual DNS queries (for testing)")
	fs.IntVar(&f.testHitRate, "hit-rate", 15, "In simulation mode, percentage of names that resolve (1-100)")
	fs.Uint64Var(&f.seed, "seed", 0, "In simulation mode, seed for reproducible results (0 = random; the seed used is printed)")
	fs.StringVar(&f.outputFile, "o", "", "Write results to file (in addition to stdout)")
	fs.IntVar(&f.attempts, "attempts", 0, "Total DNS resolution attempts per subdomain, 1 = no retry (default 1)")
	fs.IntVar(&f.retries, "retries", 0, "Deprecated: use -attempts instead")
	fs.BoolVar(&f.force, "force", false, "Continue scanning even if wildcard DNS is detected")
	fs.StringVar(&f.format, "format", "text", "Output format: text, json, jsonl, or csv")
	fs.BoolVar(&f.showRecords, "show-records", false, "In text format, append each result's records (TYPE=value)")
	fs.IntVar(&f.rate, "rate", 0, "Max DNS queries per second on the wire, all workers combined; counts every record type, retry and wildcard probe (0 = unlimited)")
	fs.StringVar(&f.recordTypes, "type", "A,AAAA", "Comma-separated DNS record types to look up: A, AAAA, CNAME")
	fs.BoolVar(&f.recursive, "recursive", false, "Recursively enumerate subdomains of discovered subdomains")
	fs.IntVar(&f.depth, "depth", 1, "Max recursion depth when -recursive is set (1 = no recursion)")
	fs.BoolVar(&f.noAbort, "no-abort", false, "Do not abort when the resolver failure rate exceeds 20% (warning is still emitted)")
	fs.IntVar(&f.maxQueries, "max-queries", 0, "Max candidate names to test (0 = unlimited); each name sends one query per record type, per attempt")
	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintln(w, "Usage: subenum -w <wordlist_file> [options] <domain>")
		fmt.Fprintln(w, "       subenum -w <wordlist_file> [options] -dL <domains_file>")
		fs.PrintDefaults()
		_, _ = fmt.Fprint(w, "\n"+exitCodesHelp)
	}
	positionals, err := parseInterspersed(fs, args)
	return f, positionals, fs, err
}

// parseInterspersed parses flags that appear anywhere in args. The standard flag
// package stops at the first non-flag argument, which silently dropped every flag
// written after the domain (#29). Arguments after a "--" terminator are all
// treated as positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		before := len(args)
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positionals, nil
		}
		consumed := args[:before-len(rest)]
		if endsWithTerminator(fs, consumed) {
			return append(positionals, rest...), nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}

// endsWithTerminator reports whether the parsed arguments ended at a "--"
// terminator, as opposed to "--" being the value of a flag such as "-o --".
func endsWithTerminator(fs *flag.FlagSet, consumed []string) bool {
	n := len(consumed)
	if n == 0 || consumed[n-1] != "--" {
		return false
	}
	if n < 2 {
		return true
	}
	prev := consumed[n-2]
	if !strings.HasPrefix(prev, "-") || strings.Contains(prev, "=") {
		return true
	}
	fl := fs.Lookup(strings.TrimLeft(prev, "-"))
	if fl == nil {
		return true
	}
	if b, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
		return true // bool flags take no separate value
	}
	return false // "--" was the value of the preceding flag
}

func validateFlags(f cliFlags, positionals []string, fs *flag.FlagSet, out *output.Writer, maxAttempts int) (string, bool) {
	if f.wordlistFile == "" || (len(positionals) == 0 && f.domainList == "") {
		// Say what is missing before the full flag list (#58).
		if f.wordlistFile == "" {
			out.Error("-w <wordlist> is required")
		}
		if len(positionals) == 0 && f.domainList == "" {
			out.Error("missing <domain> (or -dL <domains_file>)")
		}
		fs.SetOutput(os.Stderr)
		fs.Usage()
		return "", false
	}
	if f.domainList != "" && len(positionals) > 0 {
		out.Error("use either a <domain> argument or -dL, not both")
		return "", false
	}
	if len(positionals) > 1 {
		out.Error("expected exactly one domain, got %d arguments: %s (use -dL for several)", len(positionals), strings.Join(positionals, " "))
		return "", false
	}
	if f.wordlistFile == wordlist.Stdin && f.domainList == wordlist.Stdin {
		out.Error("-w and -dL cannot both read standard input")
		return "", false
	}
	if f.concurrency <= 0 {
		out.Error("Concurrency level (-t) must be greater than 0")
		return "", false
	}
	if f.concurrency > highConcurrency {
		out.Info("Warning: -t %d is very high; every worker can hold a socket open, and most resolvers rate-limit long before this", f.concurrency)
	}
	if f.timeoutMs <= 0 {
		out.Error("Timeout (-timeout) must be greater than 0")
		return "", false
	}
	if f.testHitRate < 1 || f.testHitRate > 100 {
		out.Error("Hit rate (-hit-rate) must be between 1 and 100")
		return "", false
	}
	if maxAttempts < 1 {
		out.Error("Attempts (-attempts) must be at least 1")
		return "", false
	}
	if f.rate < 0 {
		out.Error("Rate (-rate) must be 0 (unlimited) or a positive integer")
		return "", false
	}
	if f.depth < 1 {
		out.Error("Depth (-depth) must be at least 1")
		return "", false
	}
	if f.maxQueries < 0 {
		out.Error("Max queries (-max-queries) must be 0 (unlimited) or a positive integer")
		return "", false
	}
	if !f.testMode {
		if err := validate.DNSServer(f.dnsServer); err != nil {
			out.Error("DNS server %s: %v", f.dnsServer, err)
			return "", false
		}
	}
	if f.domainList != "" {
		return "", true // targets come from loadTargets
	}
	domain, notes, err := validate.NormalizeDomain(positionals[0])
	if err != nil {
		out.Error("%v", err)
		return "", false
	}
	for _, n := range notes {
		out.Info("Note: %s", n)
	}
	return domain, true
}

// loadTargets returns the apex domains to scan: the single positional domain,
// or the entries of the -dL file ("-" for stdin). Blank lines, # comments and
// duplicates are skipped; invalid domains are reported and skipped.
func loadTargets(f cliFlags, domain string, out *output.Writer) ([]string, bool) {
	if f.domainList == "" {
		return []string{domain}, true
	}
	lines, err := wordlist.ReadLines(f.domainList)
	if err != nil {
		out.Error("reading domain list: %v", err)
		return nil, false
	}
	var targets []string
	seen := make(map[string]bool)
	for _, line := range lines {
		if wordlist.IsComment(line) {
			continue
		}
		d, notes, err := validate.NormalizeDomain(line)
		if err != nil {
			out.Info("Skipping invalid domain %q in %s: %v", strings.TrimSpace(line), f.domainList, err)
			continue
		}
		for _, n := range notes {
			out.Info("Note: %s", n)
		}
		if !seen[d] {
			seen[d] = true
			targets = append(targets, d)
		}
	}
	if len(targets) == 0 {
		out.Error("domain list %s has no valid domains", f.domainList)
		return nil, false
	}
	return targets, true
}

func openOutputFile(path string, testMode bool, format output.Format, out *output.Writer) (*output.Writer, *output.File, bool) {
	if path == "" {
		return out, nil, true
	}
	f, err := output.CreateFile(path)
	if err != nil {
		out.Error("creating output file: %v", err)
		return out, nil, false
	}
	return output.New(f.Writer, testMode, format), f, true
}

// stdoutIsTerminal reports whether stdout is an interactive terminal rather than
// a pipe or file.
func stdoutIsTerminal() bool { return isTerminal(os.Stdout) }

// isTerminal reports whether f is a character device (a terminal) rather than
// a pipe or file.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// flagSet reports whether the named flag was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(fl *flag.Flag) { set = set || fl.Name == name })
	return set
}

func logVerboseStart(f cliFlags, domain string, maxAttempts int, out *output.Writer) {
	out.Info("Starting %s", formatVersion())
	if f.testMode {
		out.Info("Mode: SIMULATION (no actual DNS queries)")
		out.Info("Simulated hit rate: %d%%", f.testHitRate)
	} else {
		out.Info("Mode: LIVE DNS RESOLUTION")
	}
	out.Info("Target domain: %s", domain)
	out.Info("Wordlist: %s", f.wordlistFile)
	out.Info("Concurrency: %d workers", f.concurrency)
	out.Info("Timeout: %d ms", f.timeoutMs)
	out.Info("Attempts: %d", maxAttempts)
	if !f.testMode {
		out.Info("DNS Server: %s", f.dnsServer)
	}
	if f.outputFile != "" {
		out.Info("Output file: %s", f.outputFile)
	}
	out.Info("---")
}

func logVerboseDone(ev scan.Event, f cliFlags, outWriter *bufio.Writer, out *output.Writer) {
	out.Info("Processed %d subdomain prefixes", ev.Processed)
	if outWriter != nil {
		out.Info("Results written to: %s", f.outputFile)
	}
	if f.testMode {
		out.Info("\nNOTE: Results were simulated and no actual DNS queries were performed.")
		out.Info("This mode is intended for educational and testing purposes only.")
	}
}

func logScanBreakdown(domain string, ev scan.Event, out *output.Writer) {
	s := ev.Stats
	out.Info("Scan complete for %s", domain)
	out.Info("  resolved:  %d", s.Found)
	out.Info("  nxdomain:  %d", s.NXDomain)
	out.Info("  timeout:   %d", s.Timeout)
	out.Info("  refused:   %d", s.Refused)
	out.Info("  other:     %d", s.Other)
	out.Info("  wildcard-filtered: %d", s.WildcardFiltered)
}

func run() (code int) {
	f, positionals, fs, parseErr := parseFlags(os.Args[1:])
	if parseErr != nil {
		// The FlagSet has already printed the error and usage.
		if errors.Is(parseErr, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	// -tui counts only as a real flag, not as the value of another flag
	// (-o -tui) or an argument after "--" (#58).
	if f.tui {
		if fs.NFlag() > 1 || len(positionals) > 0 {
			fmt.Fprintln(os.Stderr, "Warning: -tui ignores every other flag and argument; set them in the form instead")
		}
		return tui.Start()
	}

	// -version answers before anything else prints, banners included (#58).
	if f.showVersion {
		fmt.Println(formatVersion())
		return 0
	}

	format, formatErr := output.ParseFormat(f.format)
	recordTypes, typesErr := dns.ParseTypes(f.recordTypes)
	maxAttempts, err := resolveAttempts(f.attempts, f.retries)
	out := output.New(nil, f.testMode, format)
	if formatErr != nil {
		out.Error("%v", formatErr)
		return exitUsage
	}
	if typesErr != nil {
		out.Error("%v", typesErr)
		return exitUsage
	}
	if err != nil {
		out.Error("%v", err)
		return exitUsage
	}

	if f.testMode {
		if f.seed == 0 {
			f.seed = rand.Uint64()
		}
		out.Info("")
		out.Info("╔════════════════════════════════════════════════════════════════════╗")
		out.Info("║  SIMULATION MODE ACTIVE - NO ACTUAL DNS QUERIES WILL BE PERFORMED  ║")
		out.Info("║  Results are artificially generated for educational purposes only  ║")
		out.Info("╚════════════════════════════════════════════════════════════════════╝")
		out.Info("Simulation seed: %d (pass -seed %d to reproduce these results)", f.seed, f.seed)
		out.Info("")
	}

	domain, ok := validateFlags(f, positionals, fs, out, maxAttempts)
	if !ok {
		return exitUsage
	}

	targets, ok := loadTargets(f, domain, out)
	if !ok {
		return 1
	}
	targetDesc := targets[0]
	if len(targets) > 1 {
		targetDesc = fmt.Sprintf("%d domains from %s", len(targets), f.domainList)
	}
	if f.verbose {
		logVerboseStart(f, targetDesc, maxAttempts, out)
	}

	// Read the wordlist before creating the output file so a bad -w path does
	// not truncate an existing -o target. It is read once (stdin can only be
	// read once) and normalized per target, since the name-length limit
	// depends on the domain.
	wordLines, err := wordlist.ReadLines(f.wordlistFile)
	if err != nil {
		out.Error("reading wordlist file: %v", err)
		return 1
	}
	if probe, _, _ := wordlist.Build(wordLines, ""); len(probe) == 0 {
		out.Error("wordlist %s has no valid entries", f.wordlistFile)
		return 1
	}

	out, outFile, ok := openOutputFile(f.outputFile, f.testMode, format, out)
	if !ok {
		return 1
	}
	var outWriter *bufio.Writer
	if outFile != nil {
		outWriter = outFile.Writer
	}
	// Bare names when piped (no "Found:" banner), human-friendly on a terminal.
	out.SetPlain(!stdoutIsTerminal())
	out.SetShowRecords(f.showRecords)
	out.SetSeed(f.seed)
	// A carriage-return progress line only makes sense on a terminal. When
	// stderr is a pipe or file (2>&1, tee, CI logs) progress is off unless
	// -progress was given explicitly, and then printed as whole lines (#78).
	if !isTerminal(os.Stderr) {
		if flagSet(fs, "progress") {
			out.SetProgressLines(true)
		} else {
			f.showProgress = false
		}
	}
	fileErrReported := false
	anyDone, anyFailed := false, false
	if outFile != nil {
		// Runs after the final return value is chosen. The results file
		// replaces an existing one only if a scan finished (#52); a failed
		// flush, close or rename means it is incomplete, so it must turn a
		// successful exit into a failure (#30). bufio errors are sticky, so a
		// failure already reported by Finish is not printed twice.
		defer func() {
			if err := outFile.Close(anyDone); err != nil {
				if !fileErrReported {
					out.Error("writing output file: %v", err)
				}
				if code == 0 {
					code = 1
				}
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	if signalReady != nil {
		close(signalReady)
	}
	var signalCode atomic.Int32 // 128+signum once a signal arrives
	go func() {
		select {
		case sig := <-sigCh:
			// Restore default handling so a second Ctrl+C force-quits a run
			// that is stuck draining (for example on a blocked stdout pipe).
			signal.Stop(sigCh)
			if sig == syscall.SIGTERM {
				out.Info("SIGTERM received, shutting down gracefully...")
				signalCode.Store(143)
			} else {
				out.Info("Interrupt received, shutting down gracefully (Ctrl+C again to force quit)...")
				signalCode.Store(130)
			}
			cancel()
		case <-ctx.Done():
		}
	}()

	// Each target is an independent scan: its own preflight, wildcard check,
	// -max-queries budget, -rate limiter and reliability guard. Results share
	// one writer, so -format json is a single array and CSV has a single
	// header. A reliability abort means the resolver is overloaded, so the
	// remaining targets are skipped rather than sent to it too (#82).
	status := make([]string, len(targets))
	failedTargets := 0
	for i, target := range targets {
		if ctx.Err() != nil {
			break
		}
		if len(targets) > 1 {
			out.Info("=== [%d/%d] %s ===", i+1, len(targets), target)
		}
		entries, duplicates, skipped := wordlist.Build(wordLines, target)
		if skipped > 0 {
			out.Info("Skipped %d invalid wordlist entries (not valid DNS labels, or name longer than 253 characters)", skipped)
		}
		if f.verbose {
			out.Info("Total wordlist entries: %d", len(entries))
			if duplicates > 0 {
				out.Info("Removed %d duplicate wordlist entries", duplicates)
			}
		}
		if len(entries) == 0 {
			out.Error("no valid wordlist entries for %s", target)
			anyFailed = true
			status[i] = "failed"
			failedTargets++
			continue
		}
		done, failed, resolverAbort := scanTarget(ctx, f, target, entries, maxAttempts, recordTypes, out, outWriter)
		anyDone = anyDone || done
		anyFailed = anyFailed || failed
		status[i] = "ok"
		if failed {
			status[i] = "failed"
			failedTargets++
		}
		if resolverAbort && i < len(targets)-1 {
			out.Error("resolver %s looks overloaded; skipping the %d remaining targets (use -no-abort to continue)", f.dnsServer, len(targets)-1-i)
			for j := i + 1; j < len(targets); j++ {
				status[j] = "skipped"
				failedTargets++
			}
			break
		}
	}
	if len(targets) > 1 {
		out.Info("Targets:")
		for i, target := range targets {
			st := status[i]
			if st == "" {
				st = "not run"
			}
			out.Info("  %-8s %s", st, target)
		}
	}

	// Finalize structured output only if at least one scan finished, so an
	// early error (such as wildcard detection without -force) does not emit an
	// empty JSON array or a bare CSV header. The deferred file flush/close
	// registered above runs after this. Reliability abort still emits
	// EventDone with partial results, so Finish runs there.
	if anyDone {
		if err := out.Finish(); err != nil {
			out.Error("writing output file: %v", err)
			fileErrReported = true
		}
		if f.testMode && !f.verbose {
			out.Info("NOTE: these results are SIMULATED; no DNS queries were sent (seed %d).", f.seed)
		}
	}
	if c := signalCode.Load(); c != 0 {
		// Shell convention 128+signum: partial results were flushed above,
		// but callers can tell an interrupted scan apart from success or failure.
		return int(c)
	}
	if fileErrReported {
		return exitFailure
	}
	if len(targets) > 1 && failedTargets > 0 && failedTargets < len(targets) {
		return exitPartial
	}
	if anyFailed {
		return exitFailure
	}
	return exitOK
}

// scanTarget runs one domain's scan and streams its events to out. It reports
// whether the scan finished (EventDone arrived), whether it should count as a
// failure for the exit code, and whether the reliability guard aborted it.
func scanTarget(ctx context.Context, f cliFlags, domain string, entries []string, maxAttempts int, recordTypes []string, out *output.Writer, outWriter *bufio.Writer) (sawDone, failed, resolverAbort bool) {
	cfg := scan.Config{
		Domain:      domain,
		Entries:     entries,
		Concurrency: f.concurrency,
		Timeout:     time.Duration(f.timeoutMs) * time.Millisecond,
		DNSServer:   f.dnsServer,
		Simulate:    f.testMode,
		HitRate:     f.testHitRate,
		Seed:        f.seed,
		Attempts:    maxAttempts,
		Force:       f.force,
		Verbose:     f.verbose,
		Logf:        out.Info, // serialized with the progress line (#36)
		Rate:        f.rate,
		Types:       recordTypes,
		Recursive:   f.recursive,
		Depth:       f.depth,
		NoAbort:     f.noAbort,
		MaxQueries:  f.maxQueries,
	}

	events := make(chan scan.Event, 64)
	go scan.Run(ctx, cfg, events)

	progressStarted := false
	sawError := false
	finishProgress := func() {
		if progressStarted {
			out.ProgressDone()
			progressStarted = false
		}
	}
	for ev := range events {
		switch ev.Kind {
		case scan.EventResult:
			out.Result(ev.Domain, ev.Records)
		case scan.EventProgress:
			if f.showProgress && ev.Total > 0 {
				progressStarted = true
				pct := float64(ev.Processed) / float64(ev.Total) * 100
				out.Progress(pct, ev.Processed, ev.Total, ev.Found)
			}
		case scan.EventNotice:
			out.Info("%s", ev.Message)
		case scan.EventError:
			out.Error("%s", ev.Message)
			sawError = true
			finishProgress()
			// Keep draining so EventDone (and Stats) can still arrive after a
			// reliability abort. Early errors such as wildcard detection close
			// the channel without EventDone.
		case scan.EventDone:
			finishProgress()
			sawDone = true
			logScanBreakdown(domain, ev, out)
			if f.verbose {
				logVerboseDone(ev, f, outWriter, out)
			}
		}
	}
	// An error fails the run unless the scan finished under -no-abort.
	// The reliability guard is the only error that still lets EventDone
	// arrive; without -no-abort it cancelled the scan.
	resolverAbort = sawDone && sawError && !f.noAbort
	return sawDone, sawError && (!sawDone || !f.noAbort), resolverAbort
}

// resolveAttempts merges the -attempts and deprecated -retries flags.
func resolveAttempts(attempts, retries int) (int, error) {
	attemptsSet := attempts != 0
	retriesSet := retries != 0

	switch {
	case attemptsSet && retriesSet:
		return 0, fmt.Errorf("cannot use both -attempts and -retries; use -attempts only")
	case retriesSet:
		fmt.Fprintln(os.Stderr, "Warning: -retries is deprecated, use -attempts instead")
		return retries, nil
	case attemptsSet:
		return attempts, nil
	default:
		return 1, nil
	}
}
