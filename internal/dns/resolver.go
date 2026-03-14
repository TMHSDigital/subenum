package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"time"
)

// ResolveDomain performs a single DNS lookup for the given domain using the
// specified server and timeout. It returns true if the domain resolves.
func ResolveDomain(ctx context.Context, domain string, timeout time.Duration, dnsServer string, verbose bool) bool {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(dialCtx, "udp", dnsServer)
		},
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	ips, err := resolver.LookupHost(timeoutCtx, domain)
	elapsed := time.Since(start)

	if verbose && err == nil {
		fmt.Fprintf(os.Stderr, "Resolved: %s (IP: %s) in %s\n", domain, ips[0], elapsed)
	} else if verbose {
		fmt.Fprintf(os.Stderr, "Failed to resolve: %s (Error: %v) in %s\n", domain, err, elapsed)
	}

	return err == nil
}

// ResolveDomainWithRetry calls ResolveDomain up to maxAttempts times, respecting
// ctx cancellation between attempts with a linear backoff delay.
func ResolveDomainWithRetry(ctx context.Context, domain string, timeout time.Duration, dnsServer string, verbose bool, maxAttempts int) bool {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return false
		}
		if ResolveDomain(ctx, domain, timeout, dnsServer, verbose) {
			return true
		}
		if attempt < maxAttempts-1 {
			select {
			case <-time.After(time.Duration(50*(attempt+1)) * time.Millisecond):
			case <-ctx.Done():
				return false
			}
		}
	}
	return false
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
