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
	"math/rand"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	ProgramName      = "subenum"
	Version          = "0.3.0"
	DefaultDNSServer = "8.8.8.8:53"
	DefaultRetries   = 1
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// validateDNSServer checks that the DNS server string is a valid ip:port.
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

// validateDomain checks that a domain name is syntactically valid.
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

// sanitizeLine trims whitespace from a wordlist entry.
// Returns an empty string for blank or whitespace-only lines.
func sanitizeLine(s string) string {
	return strings.TrimSpace(s)
}

func main() {
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
	retries := flag.Int("retries", DefaultRetries, "Number of DNS retry attempts per subdomain")
	flag.Parse()

	if *testMode {
		fmt.Printf("\n")
		fmt.Printf("╔════════════════════════════════════════════════════════════════════╗\n")
		fmt.Printf("║  SIMULATION MODE ACTIVE - NO ACTUAL DNS QUERIES WILL BE PERFORMED  ║\n")
		fmt.Printf("║  Results are artificially generated for educational purposes only  ║\n")
		fmt.Printf("╚════════════════════════════════════════════════════════════════════╝\n\n")
	}

	if *showVersion {
		fmt.Printf("%s v%s\n", ProgramName, Version)
		if *testMode {
			fmt.Println("Running in SIMULATION mode")
		}
		os.Exit(0)
	}

	if *wordlistFile == "" || flag.NArg() == 0 {
		fmt.Println("Usage: subenum -w <wordlist_file> [options] <domain>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *concurrency <= 0 {
		fmt.Println("Error: Concurrency level (-t) must be greater than 0")
		os.Exit(1)
	}

	if *timeoutMs <= 0 {
		fmt.Println("Error: Timeout (-timeout) must be greater than 0")
		os.Exit(1)
	}

	if *testHitRate < 1 || *testHitRate > 100 {
		fmt.Println("Error: Hit rate (-hit-rate) must be between 1 and 100")
		os.Exit(1)
	}

	if *retries < 1 {
		fmt.Println("Error: Retries (-retries) must be at least 1")
		os.Exit(1)
	}

	if !*testMode {
		if err := validateDNSServer(*dnsServer); err != nil {
			fmt.Printf("Error: DNS server %s: %v\n", *dnsServer, err)
			os.Exit(1)
		}
	}

	domain := flag.Arg(0)
	if err := validateDomain(domain); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	timeout := time.Duration(*timeoutMs) * time.Millisecond

	// Set up output file with a buffered writer if requested.
	// Defers are LIFO: Flush runs before Close.
	var outWriter *bufio.Writer
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		outWriter = bufio.NewWriter(f)
		defer outWriter.Flush()
	}

	if *verbose {
		fmt.Printf("Starting %s v%s\n", ProgramName, Version)
		if *testMode {
			fmt.Printf("Mode: SIMULATION (no actual DNS queries)\n")
			fmt.Printf("Simulated hit rate: %d%%\n", *testHitRate)
		} else {
			fmt.Printf("Mode: LIVE DNS RESOLUTION\n")
		}
		fmt.Printf("Target domain: %s\n", domain)
		fmt.Printf("Wordlist: %s\n", *wordlistFile)
		fmt.Printf("Concurrency: %d workers\n", *concurrency)
		fmt.Printf("Timeout: %d ms\n", *timeoutMs)
		fmt.Printf("Retries: %d\n", *retries)
		if !*testMode {
			fmt.Printf("DNS Server: %s\n", *dnsServer)
		}
		if *outputFile != "" {
			fmt.Printf("Output file: %s\n", *outputFile)
		}
		fmt.Println("---")
	}

	file, err := os.Open(*wordlistFile)
	if err != nil {
		fmt.Printf("Error opening wordlist file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Count non-blank lines for accurate progress reporting.
	var totalWords int64 = 0
	if *showProgress {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if sanitizeLine(scanner.Text()) != "" {
				totalWords++
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error counting wordlist lines: %v\n", err)
		}

		if _, err := file.Seek(0, 0); err != nil {
			fmt.Printf("Error seeking wordlist file: %v\n", err)
			os.Exit(1)
		}

		if *verbose {
			fmt.Printf("Total wordlist entries: %d\n", totalWords)
		}
	}

	// Set up graceful shutdown via SIGINT/SIGTERM.
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

	subdomains := make(chan string)
	var wg sync.WaitGroup
	var processedWords int64 = 0
	var foundSubdomains int64 = 0
	var outputMu sync.Mutex

	if *showProgress && totalWords > 0 {
		ticker := time.NewTicker(2 * time.Second)
		done := make(chan bool, 1)
		go func() {
			for {
				select {
				case <-done:
					ticker.Stop()
					return
				case <-ticker.C:
					processed := atomic.LoadInt64(&processedWords)
					found := atomic.LoadInt64(&foundSubdomains)
					progress := float64(processed) / float64(totalWords) * 100
					outputMu.Lock()
					fmt.Printf("\rProgress: %.1f%% (%d/%d) | Found: %d ",
						progress, processed, totalWords, found)
					outputMu.Unlock()
				}
			}
		}()

		defer func() {
			done <- true
			fmt.Println()
		}()
	}

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomainPrefix := range subdomains {
				if ctx.Err() != nil {
					atomic.AddInt64(&processedWords, 1)
					continue
				}

				fullDomain := subdomainPrefix + "." + domain
				var resolved bool

				if *testMode {
					resolved = simulateResolution(fullDomain, *testHitRate, *verbose)
				} else {
					resolved = resolveDomainWithRetry(ctx, fullDomain, timeout, *dnsServer, *verbose, *retries)
				}

				if resolved {
					outputMu.Lock()
					if *testMode {
						fmt.Printf("Found (SIMULATED): %s\n", fullDomain)
					} else {
						fmt.Printf("Found: %s\n", fullDomain)
					}
					if outWriter != nil {
						fmt.Fprintln(outWriter, fullDomain)
					}
					outputMu.Unlock()
					atomic.AddInt64(&foundSubdomains, 1)
				}
				atomic.AddInt64(&processedWords, 1)
			}
		}()
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := sanitizeLine(scanner.Text())
		if line == "" {
			continue
		}
		select {
		case <-ctx.Done():
			goto done
		case subdomains <- line:
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading wordlist file: %v\n", err)
	}

done:
	close(subdomains)
	wg.Wait()

	if *verbose {
		fmt.Printf("\nScan completed for %s\n", domain)
		fmt.Printf("Processed %d subdomain prefixes\n", atomic.LoadInt64(&processedWords))
		fmt.Printf("Found %d ", atomic.LoadInt64(&foundSubdomains))
		if *testMode {
			fmt.Printf("simulated ")
		}
		fmt.Printf("subdomains\n")

		if outWriter != nil {
			fmt.Printf("Results written to: %s\n", *outputFile)
		}

		if *testMode {
			fmt.Println("\nNOTE: Results were simulated and no actual DNS queries were performed.")
			fmt.Println("This mode is intended for educational and testing purposes only.")
		}
	}
}

func simulateResolution(domain string, hitRate int, verbose bool) bool {
	commonSubdomains := []string{
		"www", "mail", "ftp", "blog",
		"api", "dev", "staging", "test",
		"admin", "portal", "app", "secure",
	}

	for _, sub := range commonSubdomains {
		if strings.HasPrefix(domain, sub+".") {
			if verbose {
				fakeTiming := time.Duration(50+rand.Intn(200)) * time.Millisecond
				fakeIP := fmt.Sprintf("192.168.%d.%d", rand.Intn(255), 1+rand.Intn(254))
				fmt.Printf("Resolved (SIMULATED): %s (IP: %s) in %s\n", domain, fakeIP, fakeTiming)
			}
			return rand.Intn(100) < 90
		}
	}

	result := rand.Intn(100) < hitRate

	if verbose {
		fakeTiming := time.Duration(100+rand.Intn(500)) * time.Millisecond
		if result {
			fakeIP := fmt.Sprintf("10.%d.%d.%d", rand.Intn(255), rand.Intn(255), 1+rand.Intn(254))
			fmt.Printf("Resolved (SIMULATED): %s (IP: %s) in %s\n", domain, fakeIP, fakeTiming)
		} else {
			fmt.Printf("Failed to resolve (SIMULATED): %s (Error: no such host) in %s\n", domain, fakeTiming)
		}
	}

	return result
}

// resolveDomainWithRetry calls resolveDomain up to maxRetries times, respecting ctx cancellation
// between attempts with an exponential backoff delay.
func resolveDomainWithRetry(ctx context.Context, domain string, timeout time.Duration, dnsServer string, verbose bool, maxRetries int) bool {
	for attempt := 0; attempt < maxRetries; attempt++ {
		if ctx.Err() != nil {
			return false
		}
		if resolveDomain(ctx, domain, timeout, dnsServer, verbose) {
			return true
		}
		if attempt < maxRetries-1 {
			select {
			case <-time.After(time.Duration(50*(attempt+1)) * time.Millisecond):
			case <-ctx.Done():
				return false
			}
		}
	}
	return false
}

func resolveDomain(ctx context.Context, domain string, timeout time.Duration, dnsServer string, verbose bool) bool {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(dialCtx, "udp", dnsServer)
		},
	}

	// Derive timeout from the caller's context so cancellation is propagated.
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	ips, err := resolver.LookupHost(timeoutCtx, domain)
	elapsed := time.Since(start)

	if verbose && err == nil {
		fmt.Printf("Resolved: %s (IP: %s) in %s\n", domain, ips[0], elapsed)
	} else if verbose {
		fmt.Printf("Failed to resolve: %s (Error: %v) in %s\n", domain, err, elapsed)
	}

	return err == nil
}
