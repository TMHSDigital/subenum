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
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/tui"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

const (
	ProgramName      = "subenum"
	Version          = "0.4.0"
	DefaultDNSServer = "8.8.8.8:53"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func validateDNSServer(server string) error {
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return fmt.Errorf("invalid format, expected ip:port (e.g., %s): %w", DefaultDNSServer, err)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("invalid IP address: %s", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %s (must be 1-65535)", portStr)
	}
	return nil
}

func validateDomain(domain string) error {
	if len(domain) == 0 {
		return fmt.Errorf("domain cannot be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain exceeds maximum length of 253 characters")
	}
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}
	return nil
}

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

func run() int {
	flag.Bool("tui", false, "Launch the interactive terminal UI (all other flags are ignored)")
	wordlistFile := flag.String("w", "", "Path to the wordlist file")
	concurrency := flag.Int("t", 100, "Number of concurrent workers")
	timeoutMs := flag.Int("timeout", 1000, "DNS lookup timeout in milliseconds")
	dnsServer := flag.String("dns-server", DefaultDNSServer, "DNS server to use (format: ip:port)")
	verbose := flag.Bool("v", false, "Enable verbose output")
	showVersion := flag.Bool("version", false, "Show version information")
	showProgress := flag.Bool("progress", true, "Show progress during scanning")
	testMode := flag.Bool("simulate", false, "Run in simulation mode without actual DNS queries (for testing)")
	testHitRate := flag.Int("hit-rate", 15, "In simulation mode, percentage of subdomains that will 'resolve' (1-100)")
	outputFile := flag.String("o", "", "Write results to file (in addition to stdout)")
	attempts := flag.Int("attempts", 0, "Total DNS resolution attempts per subdomain (1 = no retry)")
	retries := flag.Int("retries", 0, "Deprecated: use -attempts instead")
	force := flag.Bool("force", false, "Continue scanning even if wildcard DNS is detected")
	flag.Parse()

	maxAttempts, err := resolveAttempts(*attempts, *retries)

	out := output.New(nil, *testMode)

	if err != nil {
		out.Error("%v", err)
		return 1
	}

	if *testMode {
		out.Info("")
		out.Info("╔════════════════════════════════════════════════════════════════════╗")
		out.Info("║  SIMULATION MODE ACTIVE - NO ACTUAL DNS QUERIES WILL BE PERFORMED  ║")
		out.Info("║  Results are artificially generated for educational purposes only  ║")
		out.Info("╚════════════════════════════════════════════════════════════════════╝")
		out.Info("")
	}

	if *showVersion {
		fmt.Fprintf(os.Stderr, "%s v%s\n", ProgramName, Version)
		if *testMode {
			fmt.Fprintln(os.Stderr, "Running in SIMULATION mode")
		}
		return 0
	}

	if *wordlistFile == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Usage: subenum -w <wordlist_file> [options] <domain>")
		flag.PrintDefaults()
		return 1
	}

	if *concurrency <= 0 {
		out.Error("Concurrency level (-t) must be greater than 0")
		return 1
	}

	if *timeoutMs <= 0 {
		out.Error("Timeout (-timeout) must be greater than 0")
		return 1
	}

	if *testHitRate < 1 || *testHitRate > 100 {
		out.Error("Hit rate (-hit-rate) must be between 1 and 100")
		return 1
	}

	if maxAttempts < 1 {
		out.Error("Attempts (-attempts) must be at least 1")
		return 1
	}

	if !*testMode {
		if err := validateDNSServer(*dnsServer); err != nil {
			out.Error("DNS server %s: %v", *dnsServer, err)
			return 1
		}
	}

	domain := flag.Arg(0)
	if err := validateDomain(domain); err != nil {
		out.Error("%v", err)
		return 1
	}

	timeout := time.Duration(*timeoutMs) * time.Millisecond

	var outWriter *bufio.Writer
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			out.Error("creating output file: %v", err)
			return 1
		}
		outWriter = bufio.NewWriter(f)
		out = output.New(outWriter, *testMode)
		defer func() {
			if flushErr := outWriter.Flush(); flushErr != nil {
				out.Error("flushing output: %v", flushErr)
			}
			if closeErr := f.Close(); closeErr != nil {
				out.Error("closing output file: %v", closeErr)
			}
		}()
	}

	if *verbose {
		out.Info("Starting %s v%s", ProgramName, Version)
		if *testMode {
			out.Info("Mode: SIMULATION (no actual DNS queries)")
			out.Info("Simulated hit rate: %d%%", *testHitRate)
		} else {
			out.Info("Mode: LIVE DNS RESOLUTION")
		}
		out.Info("Target domain: %s", domain)
		out.Info("Wordlist: %s", *wordlistFile)
		out.Info("Concurrency: %d workers", *concurrency)
		out.Info("Timeout: %d ms", *timeoutMs)
		out.Info("Attempts: %d", maxAttempts)
		if !*testMode {
			out.Info("DNS Server: %s", *dnsServer)
		}
		if *outputFile != "" {
			out.Info("Output file: %s", *outputFile)
		}
		out.Info("---")
	}

	entries, duplicates, err := wordlist.LoadWordlist(*wordlistFile)
	if err != nil {
		out.Error("reading wordlist file: %v", err)
		return 1
	}

	totalWords := int64(len(entries))

	if *verbose {
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
		Concurrency: *concurrency,
		Timeout:     timeout,
		DNSServer:   *dnsServer,
		Simulate:    *testMode,
		HitRate:     *testHitRate,
		Attempts:    maxAttempts,
		Force:       *force,
		Verbose:     *verbose,
	}

	events := make(chan scan.Event, 64)
	go scan.Run(ctx, cfg, events)

	progressStarted := false
	for ev := range events {
		switch ev.Kind {
		case scan.EventResult:
			out.Result(ev.Domain)
		case scan.EventProgress:
			if *showProgress && totalWords > 0 {
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
			if *verbose {
				out.Info("\nScan completed for %s", domain)
				out.Info("Processed %d subdomain prefixes", ev.Processed)
				if *testMode {
					out.Info("Found %d simulated subdomains", ev.Found)
				} else {
					out.Info("Found %d subdomains", ev.Found)
				}
				if outWriter != nil {
					out.Info("Results written to: %s", *outputFile)
				}
				if *testMode {
					out.Info("\nNOTE: Results were simulated and no actual DNS queries were performed.")
					out.Info("This mode is intended for educational and testing purposes only.")
				}
			}
		}
	}
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
