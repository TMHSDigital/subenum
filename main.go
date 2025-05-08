// Copyright (c) 2025 TM Hospitality Strategies
//
// subenum - A Go-based CLI tool for subdomain enumeration.
//
// IMPORTANT LEGAL NOTICE:
// This tool is provided for educational and legitimate security testing purposes ONLY.
// Usage of this tool against any domain without explicit permission from the domain 
// owner may violate applicable local, national, and/or international laws.
//
// Users MUST:
// 1. Only scan domains they own or have explicit permission to test.
// 2. Comply with all applicable laws and regulations.
// 3. Use this tool responsibly and ethically.
//
// The developer(s) explicitly prohibit any malicious or unauthorized use of this tool
// and assume no liability for any misuse or damages resulting from its use.
// See the LICENSE file for full terms and conditions.

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Version information
const (
	ProgramName      = "subenum"
	Version          = "0.2.0"
	DefaultDNSServer = "8.8.8.8:53" // Google's public DNS
)

func main() {
	// Parse command-line flags
	wordlistFile := flag.String("w", "", "Path to the wordlist file")
	concurrency := flag.Int("t", 100, "Number of concurrent workers")
	timeoutMs := flag.Int("timeout", 1000, "DNS lookup timeout in milliseconds")
	dnsServer := flag.String("dns-server", DefaultDNSServer, "DNS server to use (format: ip:port)")
	verbose := flag.Bool("v", false, "Enable verbose output")
	showVersion := flag.Bool("version", false, "Show version information")
	showProgress := flag.Bool("progress", true, "Show progress during scanning")
	testMode := flag.Bool("simulate", false, "Run in simulation mode without actual DNS queries (for testing)")
	testHitRate := flag.Int("hit-rate", 15, "In simulation mode, percentage of subdomains that will 'resolve' (1-100)")
	flag.Parse()

	// Add a warning banner when simulation mode is enabled
	if *testMode {
		fmt.Printf("\n")
		fmt.Printf("╔════════════════════════════════════════════════════════════════════╗\n")
		fmt.Printf("║  SIMULATION MODE ACTIVE - NO ACTUAL DNS QUERIES WILL BE PERFORMED  ║\n")
		fmt.Printf("║  Results are artificially generated for educational purposes only  ║\n")
		fmt.Printf("╚════════════════════════════════════════════════════════════════════╝\n\n")
	}

	// Show version if requested
	if *showVersion {
		fmt.Printf("%s v%s\n", ProgramName, Version)
		if *testMode {
			fmt.Println("Running in SIMULATION mode")
		}
		os.Exit(0)
	}

	// Validate required arguments
	if *wordlistFile == "" || flag.NArg() == 0 {
		fmt.Println("Usage: subenum -w <wordlist_file> <domain>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Validate numeric parameters
	if *concurrency <= 0 {
		fmt.Println("Error: Concurrency level (-t) must be greater than 0")
		os.Exit(1)
	}
	
	if *timeoutMs <= 0 {
		fmt.Println("Error: Timeout (-timeout) must be greater than 0")
		os.Exit(1)
	}

	// Validate hit rate for simulation mode
	if *testHitRate < 1 || *testHitRate > 100 {
		fmt.Println("Error: Hit rate (-hit-rate) must be between 1 and 100")
		os.Exit(1)
	}

	// Validate DNS server format if not in test mode
	if !*testMode && !strings.Contains(*dnsServer, ":") {
		fmt.Printf("Error: DNS server must be in format ip:port (e.g., %s)\n", DefaultDNSServer)
		os.Exit(1)
	}

	domain := flag.Arg(0)
	timeout := time.Duration(*timeoutMs) * time.Millisecond

	// Verbose info about settings
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
		if !*testMode {
			fmt.Printf("DNS Server: %s\n", *dnsServer)
		}
		fmt.Println("---")
	}

	// Initialize random number generator for simulation mode
	if *testMode {
		rand.Seed(time.Now().UnixNano())
	}

	// Open wordlist
	file, err := os.Open(*wordlistFile)
	if err != nil {
		fmt.Printf("Error opening wordlist file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Count total lines for progress reporting
	var totalWords int64 = 0
	if *showProgress {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			totalWords++
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error counting wordlist lines: %v\n", err)
		}
		
		// Reset file position to beginning
		file.Seek(0, 0)
		
		if *verbose {
			fmt.Printf("Total wordlist entries: %d\n", totalWords)
		}
	}

	// Channel for subdomain prefixes
	subdomains := make(chan string)
	var wg sync.WaitGroup
	var processedWords int64 = 0
	var foundSubdomains int64 = 0

	// Progress reporting goroutine
	if *showProgress && totalWords > 0 {
		ticker := time.NewTicker(2 * time.Second)
		done := make(chan bool)
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
					fmt.Printf("\rProgress: %.1f%% (%d/%d) | Found: %d ", 
						progress, processed, totalWords, found)
				}
			}
		}()
		
		// Clean up the progress goroutine when main() exits
		defer func() {
			done <- true
			// Print a newline after the last progress update
			fmt.Println()
		}()
	}

	// Worker pool
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomainPrefix := range subdomains {
				fullDomain := subdomainPrefix + "." + domain
				var resolved bool
				
				if *testMode {
					// In test mode, simulate DNS resolution without actual queries
					resolved = simulateResolution(fullDomain, *testHitRate, *verbose)
				} else {
					// In normal mode, perform actual DNS resolution
					resolved = resolveDomain(fullDomain, timeout, *dnsServer, *verbose)
				}
				
				if resolved {
					if *testMode {
						fmt.Printf("Found (SIMULATED): %s\n", fullDomain)
					} else {
						fmt.Printf("Found: %s\n", fullDomain)
					}
					atomic.AddInt64(&foundSubdomains, 1)
				}
				atomic.AddInt64(&processedWords, 1)
			}
		}()
	}

	// Read wordlist and send to workers
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomains <- scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading wordlist file: %v\n", err)
	}

	close(subdomains)
	wg.Wait()
	
	// Final summary
	if *verbose {
		fmt.Printf("\nScan completed for %s\n", domain)
		fmt.Printf("Processed %d subdomain prefixes\n", totalWords)
		fmt.Printf("Found %d ", atomic.LoadInt64(&foundSubdomains))
		if *testMode {
			fmt.Printf("simulated ")
		}
		fmt.Printf("subdomains\n")
		
		if *testMode {
			fmt.Println("\nNOTE: Results were simulated and no actual DNS queries were performed.")
			fmt.Println("This mode is intended for educational and testing purposes only.")
		}
	}
}

// simulateResolution simulates DNS resolution for testing purposes
// without making actual network requests
func simulateResolution(domain string, hitRate int, verbose bool) bool {
	// Always resolve common subdomains for more realistic simulation
	commonSubdomains := []string{
		"www", "mail", "ftp", "blog", 
		"api", "dev", "staging", "test", 
		"admin", "portal", "app", "secure",
	}
	
	for _, sub := range commonSubdomains {
		if strings.HasPrefix(domain, sub+".") {
			// Simulate a successful lookup for these common subdomains
			if verbose {
				fakeTiming := time.Duration(50+rand.Intn(200)) * time.Millisecond
				fakeIP := fmt.Sprintf("192.168.%d.%d", rand.Intn(255), 1+rand.Intn(254))
				fmt.Printf("Resolved (SIMULATED): %s (IP: %s) in %s\n", domain, fakeIP, fakeTiming)
			}
			// With 90% probability, "resolve" common subdomains
			return rand.Intn(100) < 90
		}
	}
	
	// For other subdomains, use the hit rate to determine if they resolve
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

func resolveDomain(domain string, timeout time.Duration, dnsServer string, verbose bool) bool {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: timeout,
			}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
	
	start := time.Now()
	ips, err := resolver.LookupHost(context.Background(), domain)
	elapsed := time.Since(start)
	
	if verbose && err == nil {
		fmt.Printf("Resolved: %s (IP: %s) in %s\n", domain, ips[0], elapsed)
	} else if verbose {
		fmt.Printf("Failed to resolve: %s (Error: %v) in %s\n", domain, err, elapsed)
	}
	
	return err == nil
} 