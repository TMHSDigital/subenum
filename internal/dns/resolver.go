package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Record is a single resolved DNS record. Type is "A", "AAAA", "CNAME", etc.
// Value is the IP address (for A/AAAA) or target name (for CNAME).
type Record struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func newResolver(timeout time.Duration, dnsServer string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(dialCtx, "udp", dnsServer)
		},
	}
}

// Resolve performs a single host lookup and returns the resolved records (A and
// AAAA), the elapsed time, and any error. It performs no logging.
func Resolve(ctx context.Context, domain string, timeout time.Duration, dnsServer string) ([]Record, time.Duration, error) {
	resolver := newResolver(timeout, dnsServer)

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	ips, err := resolver.LookupHost(timeoutCtx, domain)
	elapsed := time.Since(start)
	if err != nil {
		return nil, elapsed, err
	}

	records := make([]Record, 0, len(ips))
	for _, ip := range ips {
		typ := "A"
		if strings.Contains(ip, ":") {
			typ = "AAAA"
		}
		records = append(records, Record{Type: typ, Value: ip})
	}
	return records, elapsed, nil
}

// ResolveDomain performs a single DNS lookup for the given domain using the
// specified server and timeout. It returns true if the domain resolves (A/AAAA).
func ResolveDomain(ctx context.Context, domain string, timeout time.Duration, dnsServer string, verbose bool) bool {
	records, _, _ := ResolveWithLog(ctx, domain, timeout, dnsServer, verbose)
	return len(records) > 0
}

// ResolveWithLog wraps Resolve with the verbose stderr logging used by the CLI
// and TUI, returning the resolved records.
func ResolveWithLog(ctx context.Context, domain string, timeout time.Duration, dnsServer string, verbose bool) ([]Record, time.Duration, error) {
	records, elapsed, err := Resolve(ctx, domain, timeout, dnsServer)
	if verbose && len(records) > 0 {
		fmt.Fprintf(os.Stderr, "Resolved: %s (%s: %s) in %s\n", domain, records[0].Type, records[0].Value, elapsed)
	} else if verbose {
		fmt.Fprintf(os.Stderr, "Failed to resolve: %s (Error: %v) in %s\n", domain, err, elapsed)
	}
	return records, elapsed, err
}

// ResolveDomainWithRetry calls ResolveWithLog up to maxAttempts times, respecting
// ctx cancellation between attempts with a linear backoff delay. It returns the
// resolved records and whether resolution succeeded.
func ResolveDomainWithRetry(ctx context.Context, domain string, timeout time.Duration, dnsServer string, verbose bool, maxAttempts int) ([]Record, bool) {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, false
		}
		if records, _, _ := ResolveWithLog(ctx, domain, timeout, dnsServer, verbose); len(records) > 0 {
			return records, true
		}
		if attempt < maxAttempts-1 {
			select {
			case <-time.After(time.Duration(50*(attempt+1)) * time.Millisecond):
			case <-ctx.Done():
				return nil, false
			}
		}
	}
	return nil, false
}

// randomHex returns n random hex characters.
func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)[:n]
}

// CheckWildcard probes the domain with two random subdomains. If both resolve
// the domain almost certainly uses wildcard DNS. Returns (isWildcard, error).
func CheckWildcard(ctx context.Context, domain string, timeout time.Duration, dnsServer string) (bool, error) {
	probe1 := randomHex(32) + "." + domain
	probe2 := randomHex(32) + "." + domain

	hit1 := ResolveDomain(ctx, probe1, timeout, dnsServer, false)
	hit2 := ResolveDomain(ctx, probe2, timeout, dnsServer, false)

	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	// Both hit  -> wildcard.  One hit -> treat as wildcard (conservative).
	return hit1 || hit2, nil
}
