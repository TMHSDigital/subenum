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

// DefaultTypes is the record-type set used when none is specified; it preserves
// the historical LookupHost behavior (A and AAAA).
var DefaultTypes = []string{"A", "AAAA"}

var supportedTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true}

// ParseTypes parses a comma-separated record-type list (for example
// "A,AAAA,CNAME") into a normalized, de-duplicated, uppercase slice.
func ParseTypes(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return append([]string(nil), DefaultTypes...), nil
	}
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(s, ",") {
		t := strings.ToUpper(strings.TrimSpace(part))
		if t == "" {
			continue
		}
		if !supportedTypes[t] {
			return nil, fmt.Errorf("unsupported record type %q (want A, AAAA, or CNAME)", part)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), DefaultTypes...), nil
	}
	return out, nil
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

// ResolveTypes performs per-type DNS lookups for the requested record types and
// returns the matching records, the elapsed time, and the last lookup error (if
// any). An empty types slice falls back to DefaultTypes.
func ResolveTypes(ctx context.Context, domain string, timeout time.Duration, dnsServer string, types []string) ([]Record, time.Duration, error) {
	if len(types) == 0 {
		types = DefaultTypes
	}
	resolver := newResolver(timeout, dnsServer)
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	var records []Record
	var lastErr error
	for _, t := range types {
		switch t {
		case "A":
			ips, err := resolver.LookupIP(timeoutCtx, "ip4", domain)
			if err != nil {
				lastErr = err
				continue
			}
			for _, ip := range ips {
				records = append(records, Record{Type: "A", Value: ip.String()})
			}
		case "AAAA":
			ips, err := resolver.LookupIP(timeoutCtx, "ip6", domain)
			if err != nil {
				lastErr = err
				continue
			}
			for _, ip := range ips {
				records = append(records, Record{Type: "AAAA", Value: ip.String()})
			}
		case "CNAME":
			cname, err := resolver.LookupCNAME(timeoutCtx, domain)
			if err != nil {
				lastErr = err
				continue
			}
			// LookupCNAME returns the domain itself when there is no CNAME chain.
			if cname != "" && !strings.EqualFold(strings.TrimSuffix(cname, "."), strings.TrimSuffix(domain, ".")) {
				records = append(records, Record{Type: "CNAME", Value: strings.TrimSuffix(cname, ".")})
			}
		}
	}
	return records, time.Since(start), lastErr
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
	records, _, _ := ResolveWithLog(ctx, domain, timeout, dnsServer, verbose, DefaultTypes)
	return len(records) > 0
}

// ResolveWithLog wraps ResolveTypes with the verbose stderr logging used by the
// CLI and TUI, returning the resolved records for the requested types.
func ResolveWithLog(ctx context.Context, domain string, timeout time.Duration, dnsServer string, verbose bool, types []string) ([]Record, time.Duration, error) {
	records, elapsed, err := ResolveTypes(ctx, domain, timeout, dnsServer, types)
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
func ResolveDomainWithRetry(ctx context.Context, domain string, timeout time.Duration, dnsServer string, verbose bool, maxAttempts int, types []string) ([]Record, bool) {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, false
		}
		if records, _, _ := ResolveWithLog(ctx, domain, timeout, dnsServer, verbose, types); len(records) > 0 {
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
