package dns

import (
	"context"
	"crypto/rand"
	"errors"
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

// Outcome is a coarse classification of one resolver attempt so callers can
// tell a definitive negative (NXDOMAIN) apart from an infrastructure failure.
type Outcome int

const (
	OutcomeFound Outcome = iota
	// OutcomeNXDomain is a definitive negative: the name does not exist, or it
	// exists but has no records of the requested types (NODATA). Go's resolver
	// already reports NODATA as not-found for A/AAAA; CNAME is folded in here too.
	OutcomeNXDomain
	OutcomeTimeout
	OutcomeRefused
	OutcomeOther
	// OutcomeCanceled means the scan context was cancelled mid-lookup. It says
	// nothing about the resolver and must not be counted as a failure.
	OutcomeCanceled
)

// Classify maps a resolver error onto a coarse outcome so callers can tell a
// definitive negative (NXDOMAIN) apart from an infrastructure failure.
func Classify(err error) Outcome {
	if err == nil {
		return OutcomeFound
	}
	if errors.Is(err, context.Canceled) {
		return OutcomeCanceled
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		switch {
		case de.IsNotFound:
			return OutcomeNXDomain
		case de.IsTimeout:
			return OutcomeTimeout
		}
		if strings.Contains(strings.ToLower(de.Err), "refused") {
			return OutcomeRefused
		}
	}
	return OutcomeOther
}

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

// NewResolver returns a PreferGo resolver that always dials dnsServer. The Dial
// hook honors the network argument so a truncated UDP response can fall back to TCP.
func NewResolver(timeout time.Duration, dnsServer string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(dialCtx, network, dnsServer)
		},
	}
}

// fqdn makes domain absolute. Without the trailing dot Go's resolver may also
// try every resolv.conf search suffix (and try them first when the name has
// fewer dots than ndots, as in Kubernetes pods), multiplying queries for each
// missing name.
func fqdn(domain string) string {
	if strings.HasSuffix(domain, ".") {
		return domain
	}
	return domain + "."
}

// queriesPerType is how many DNS queries one lookup of each type puts on the
// wire. Go's LookupCNAME resolves the name with both A and AAAA queries and
// reads the canonical name from the answer chain.
var queriesPerType = map[string]int{"A": 1, "AAAA": 1, "CNAME": 2}

// ResolveTypes performs per-type DNS lookups for the requested record types and
// returns the matching records, the time spent in lookups, and the most severe lookup
// error (if any). An empty types slice falls back to DefaultTypes. The caller
// should reuse a single *net.Resolver across lookups (see scan.Run).
//
// Each type gets its own timeout, so a slow A answer cannot starve AAAA or
// CNAME. If ctx carries a RateLimiter (see WithLimiter), each type first waits
// for one slot per query it will send; the timeout starts only after that.
func ResolveTypes(ctx context.Context, resolver *net.Resolver, domain string, timeout time.Duration, types []string) ([]Record, time.Duration, error) {
	if len(types) == 0 {
		types = DefaultTypes
	}
	lim := limiterFrom(ctx)
	name := fqdn(domain)
	var elapsed time.Duration
	var records []Record
	var worstErr error
	for _, t := range types {
		for i := 0; i < queriesPerType[t]; i++ {
			if err := lim.Wait(ctx); err != nil {
				return records, elapsed, err
			}
		}
		lookupCtx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		recs, err := lookupType(lookupCtx, resolver, name, domain, t)
		elapsed += time.Since(start)
		cancel()
		if err != nil {
			worstErr = worse(worstErr, err)
			continue
		}
		records = append(records, recs...)
	}
	return records, elapsed, worstErr
}

// worse keeps the more severe of two lookup errors. Any infrastructure failure
// (timeout, refused, SERVFAIL, cancellation) outranks a not-found answer: a name
// is a definitive negative only if every requested type said so. Otherwise an
// A SERVFAIL followed by an AAAA NXDOMAIN would read as NXDOMAIN and never be
// retried (#31).
func worse(cur, next error) error {
	if cur == nil {
		return next
	}
	if Classify(cur) == OutcomeNXDomain && Classify(next) != OutcomeNXDomain {
		return next
	}
	return cur
}

func lookupType(ctx context.Context, resolver *net.Resolver, name, domain, t string) ([]Record, error) {
	switch t {
	case "A", "AAAA":
		network := "ip4"
		if t == "AAAA" {
			network = "ip6"
		}
		ips, err := resolver.LookupIP(ctx, network, name)
		if err != nil {
			return nil, err
		}
		recs := make([]Record, 0, len(ips))
		for _, ip := range ips {
			recs = append(recs, Record{Type: t, Value: ip.String()})
		}
		return recs, nil
	case "CNAME":
		cname, err := resolver.LookupCNAME(ctx, name)
		if err != nil {
			return nil, err
		}
		// LookupCNAME returns the domain itself when there is no CNAME chain.
		if cname != "" && !strings.EqualFold(strings.TrimSuffix(cname, "."), strings.TrimSuffix(domain, ".")) {
			return []Record{{Type: "CNAME", Value: strings.TrimSuffix(cname, ".")}}, nil
		}
	}
	return nil, nil
}

// ResolveDomain performs a single DNS lookup for the given domain using the
// specified resolver and timeout. It returns true if the domain resolves (A/AAAA).
func ResolveDomain(ctx context.Context, resolver *net.Resolver, domain string, timeout time.Duration, verbose bool) bool {
	records, _, _ := ResolveWithLog(ctx, resolver, domain, timeout, verbose, DefaultTypes)
	return len(records) > 0
}

// ResolveWithLog wraps ResolveTypes with the verbose stderr logging used by the
// CLI and TUI, returning the resolved records for the requested types.
func ResolveWithLog(ctx context.Context, resolver *net.Resolver, domain string, timeout time.Duration, verbose bool, types []string) ([]Record, time.Duration, error) {
	records, elapsed, err := ResolveTypes(ctx, resolver, domain, timeout, types)
	if verbose && len(records) > 0 {
		fmt.Fprintf(os.Stderr, "Resolved: %s (%s: %s) in %s\n", domain, records[0].Type, records[0].Value, elapsed)
	} else if verbose {
		fmt.Fprintf(os.Stderr, "Failed to resolve: %s (Error: %v) in %s\n", domain, err, elapsed)
	}
	return records, elapsed, err
}

// ResolveDomainWithRetry calls ResolveWithLog up to maxAttempts times, respecting
// ctx cancellation between attempts with a linear backoff delay. It returns the
// resolved records and a classified outcome for the last attempt.
func ResolveDomainWithRetry(ctx context.Context, resolver *net.Resolver, domain string, timeout time.Duration, verbose bool, maxAttempts int, types []string) ([]Record, Outcome) {
	last := OutcomeOther
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, OutcomeCanceled
		}
		records, _, err := ResolveWithLog(ctx, resolver, domain, timeout, verbose, types)
		if len(records) > 0 {
			return records, OutcomeFound
		}
		last = Classify(err)
		if last == OutcomeFound {
			// Lookup succeeded but produced no records of the requested types
			// (for example -type CNAME on a name with only A records). That is a
			// definitive negative, not a resolver failure (#28).
			last = OutcomeNXDomain
		}
		if last == OutcomeNXDomain || last == OutcomeCanceled {
			return nil, last
		}
		if attempt < maxAttempts-1 {
			select {
			case <-time.After(time.Duration(50*(attempt+1)) * time.Millisecond):
			case <-ctx.Done():
				return nil, OutcomeCanceled
			}
		}
	}
	return nil, last
}

// randomHex returns n random hex characters.
func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)[:n]
}

// CheckWildcard probes the domain with two random subdomains, looking up the
// same record types the scan will request (empty means DefaultTypes), so a
// CNAME wildcard is fingerprinted when -type includes CNAME. If either probe
// resolves the domain is treated as wildcard (conservative). The returned
// record slice is the union of both probe answers and is the fingerprint used
// to filter later results. Returns (isWildcard, fingerprint, error).
func CheckWildcard(ctx context.Context, resolver *net.Resolver, domain string, timeout time.Duration, types []string) (bool, []Record, error) {
	if len(types) == 0 {
		types = DefaultTypes
	}
	probe1 := randomHex(32) + "." + domain
	probe2 := randomHex(32) + "." + domain

	r1, _, _ := ResolveTypes(ctx, resolver, probe1, timeout, types)
	r2, _, _ := ResolveTypes(ctx, resolver, probe2, timeout, types)

	if ctx.Err() != nil {
		return false, nil, ctx.Err()
	}

	fp := unionRecords(r1, r2)
	return len(r1) > 0 || len(r2) > 0, fp, nil
}

func unionRecords(a, b []Record) []Record {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]Record, 0, len(a)+len(b))
	for _, recs := range [][]Record{a, b} {
		for _, r := range recs {
			k := r.Type + "\x00" + r.Value
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, r)
		}
	}
	return out
}
