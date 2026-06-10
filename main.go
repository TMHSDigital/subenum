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
	"flag"
	"fmt"
	"os"
	"os/signal"
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
	Version          = "0.6.0"
	DefaultDNSServer = "8.8.8.8:53"
)

func main() {
	// Fast-path: if -tui is the first argument, launch the TUI immediately
	// before flag.Parse() consumes everything else.
	for _, arg := range os.Args[1:] {
		if arg == "-tui" || arg == "--tui" {
			os.Exit(tui.Start())
		}
	}
	os.Exit(run())
}

// cliFlags holds all parsed command-line flag values.
type cliFlags struct {
	wordlistFile string
	concurrency  int
	timeoutMs    int
	dnsServer    string
	verbose      bool
	showVersion  bool
	showProgress bool
	testMode     bool
	testHitRate  int
	outputFile   string
	attempts     int
	retries      int
	force        bool
	format       string
	rate         int
	recordTypes  string
	recursive    bool
	depth        int
}

func parseFlags() cliFlags {
	var f cliFlags
	flag.Bool("tui", false, "Launch the interactive terminal UI (all other flags are ignored)")
	flag.StringVar(&f.wordlistFile, "w", "", "Path to the wordlist file")
	flag.IntVar(&f.concurrency, "t", 100, "Number of concurrent workers")
	flag.IntVar(&f.timeoutMs, "timeout", 1000, "DNS lookup timeout in milliseconds")
	flag.StringVar(&f.dnsServer, "dns-server", DefaultDNSServer, "DNS server to use (format: ip:port)")
	flag.BoolVar(&f.verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&f.showVersion, "version", false, "Show version information")
	flag.BoolVar(&f.showProgress, "progress", true, "Show progress during scanning")
	flag.BoolVar(&f.testMode, "simulate", false, "Run in simulation mode without actual DNS queries (for testing)")
	flag.IntVar(&f.testHitRate, "hit-rate", 15, "In simulation mode, percentage of subdomains that will 'resolve' (1-100)")
	flag.StringVar(&f.outputFile, "o", "", "Write results to file (in addition to stdout)")
	flag.IntVar(&f.attempts, "attempts", 0, "Total DNS resolution attempts per subdomain (1 = no retry)")
	flag.IntVar(&f.retries, "retries", 0, "Deprecated: use -attempts instead")
	flag.BoolVar(&f.force, "force", false, "Continue scanning even if wildcard DNS is detected")
	flag.StringVar(&f.format, "format", "text", "Output format: text, json, or csv")
	flag.IntVar(&f.rate, "rate", 0, "Max DNS queries per second across all workers (0 = unlimited)")
	flag.StringVar(&f.recordTypes, "type", "A,AAAA", "Comma-separated DNS record types to look up: A, AAAA, CNAME")
	flag.BoolVar(&f.recursive, "recursive", false, "Recursively enumerate subdomains of discovered subdomains")
	flag.IntVar(&f.depth, "depth", 1, "Max recursion depth when -recursive is set (1 = no recursion)")
	flag.Parse()
	return f
}

func validateFlags(f cliFlags, out *output.Writer, maxAttempts int) (string, bool) {
	if f.wordlistFile == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Usage: subenum -w <wordlist_file> [options] <domain>")
		flag.PrintDefaults()
		return "", false
	}
	if f.concurrency <= 0 {
		out.Error("Concurrency level (-t) must be greater than 0")
		return "", false
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
	if !f.testMode {
		if err := validate.DNSServer(f.dnsServer); err != nil {
			out.Error("DNS server %s: %v", f.dnsServer, err)
			return "", false
		}
	}
	domain := flag.Arg(0)
	if err := validate.Domain(domain); err != nil {
		out.Error("%v", err)
		return "", false
	}
	return domain, true
}

func openOutputFile(path string, testMode bool, format output.Format, out *output.Writer) (*output.Writer, *bufio.Writer, *os.File, bool) {
	if path == "" {
		return out, nil, nil, true
	}
	f, err := os.Create(path)
	if err != nil {
		out.Error("creating output file: %v", err)
		return out, nil, nil, false
	}
	w := bufio.NewWriter(f)
	return output.New(w, testMode, format), w, f, true
}

func logVerboseStart(f cliFlags, domain string, maxAttempts int, out *output.Writer) {
	out.Info("Starting %s v%s", ProgramName, Version)
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
	out.Info("\nScan completed for %s", flag.Arg(0))
	out.Info("Processed %d subdomain prefixes", ev.Processed)
	if f.testMode {
		out.Info("Found %d simulated subdomains", ev.Found)
	} else {
		out.Info("Found %d subdomains", ev.Found)
	}
	if outWriter != nil {
		out.Info("Results written to: %s", f.outputFile)
	}
	if f.testMode {
		out.Info("\nNOTE: Results were simulated and no actual DNS queries were performed.")
		out.Info("This mode is intended for educational and testing purposes only.")
	}
}

func run() int {
	f := parseFlags()

	format, formatErr := output.ParseFormat(f.format)
	recordTypes, typesErr := dns.ParseTypes(f.recordTypes)
	maxAttempts, err := resolveAttempts(f.attempts, f.retries)
	out := output.New(nil, f.testMode, format)
	if formatErr != nil {
		out.Error("%v", formatErr)
		return 1
	}
	if typesErr != nil {
		out.Error("%v", typesErr)
		return 1
	}
	if err != nil {
		out.Error("%v", err)
		return 1
	}

	if f.testMode {
		out.Info("")
		out.Info("╔════════════════════════════════════════════════════════════════════╗")
		out.Info("║  SIMULATION MODE ACTIVE - NO ACTUAL DNS QUERIES WILL BE PERFORMED  ║")
		out.Info("║  Results are artificially generated for educational purposes only  ║")
		out.Info("╚════════════════════════════════════════════════════════════════════╝")
		out.Info("")
	}

	if f.showVersion {
		fmt.Fprintf(os.Stderr, "%s v%s\n", ProgramName, Version)
		if f.testMode {
			fmt.Fprintln(os.Stderr, "Running in SIMULATION mode")
		}
		return 0
	}

	domain, ok := validateFlags(f, out, maxAttempts)
	if !ok {
		return 1
	}

	out, outWriter, outFile, ok := openOutputFile(f.outputFile, f.testMode, format, out)
	if !ok {
		return 1
	}
	if outFile != nil {
		defer func() {
			if flushErr := outWriter.Flush(); flushErr != nil {
				out.Error("flushing output: %v", flushErr)
			}
			if closeErr := outFile.Close(); closeErr != nil {
				out.Error("closing output file: %v", closeErr)
			}
		}()
	}
	if f.verbose {
		logVerboseStart(f, domain, maxAttempts, out)
	}

	entries, duplicates, err := wordlist.LoadWordlist(f.wordlistFile)
	if err != nil {
		out.Error("reading wordlist file: %v", err)
		return 1
	}

	totalWords := int64(len(entries))
	if f.verbose {
		out.Info("Total wordlist entries: %d", totalWords)
		if duplicates > 0 {
			out.Info("Removed %d duplicate wordlist entries", duplicates)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			fmt.Fprintf(os.Stderr, "\nInterrupt received, shutting down gracefully...\n")
			cancel()
		case <-ctx.Done():
		}
	}()

	cfg := scan.Config{
		Domain:      domain,
		Entries:     entries,
		Concurrency: f.concurrency,
		Timeout:     time.Duration(f.timeoutMs) * time.Millisecond,
		DNSServer:   f.dnsServer,
		Simulate:    f.testMode,
		HitRate:     f.testHitRate,
		Attempts:    maxAttempts,
		Force:       f.force,
		Verbose:     f.verbose,
		Rate:        f.rate,
		Types:       recordTypes,
		Recursive:   f.recursive,
		Depth:       f.depth,
	}

	events := make(chan scan.Event, 64)
	go scan.Run(ctx, cfg, events)

	progressStarted := false
	for ev := range events {
		switch ev.Kind {
		case scan.EventResult:
			out.Result(ev.Domain, ev.Records)
		case scan.EventProgress:
			if f.showProgress && totalWords > 0 {
				progressStarted = true
				pct := float64(ev.Processed) / float64(ev.Total) * 100
				out.Progress(pct, ev.Processed, ev.Total, ev.Found)
			}
		case scan.EventWildcard:
			out.Info(ev.Message)
		case scan.EventError:
			out.Error(ev.Message)
			if progressStarted {
				out.ProgressDone()
			}
			return 1
		case scan.EventDone:
			if progressStarted {
				out.ProgressDone()
			}
			if f.verbose {
				logVerboseDone(ev, f, outWriter, out)
			}
		}
	}
	// Finalize structured output only on the success path, so an early error
	// (such as wildcard detection without -force) does not emit an empty JSON
	// array or a bare CSV header. The deferred file flush/close registered
	// above runs after this, persisting buffered output before the file closes.
	out.Finish()
	return 0
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
