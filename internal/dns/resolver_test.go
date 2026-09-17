package dns

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestResolveDomain(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"example.com":     {A: "192.0.2.1"},
		"www.example.com": {A: "192.0.2.2"},
	})
	timeout := time.Second
	r := srv.Resolver(timeout)

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{name: "existing apex", domain: "example.com.", expected: true},
		{name: "existing subdomain", domain: "www.example.com.", expected: true},
		{name: "missing domain", domain: "nope.example.com.", expected: false},
		{name: "empty domain", domain: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveDomain(context.Background(), r, tt.domain, timeout, false)
			if got != tt.expected {
				t.Errorf("ResolveDomain(%q) = %v, want %v", tt.domain, got, tt.expected)
			}
		})
	}
}

func TestResolveDomainTimeout(t *testing.T) {
	addr := startBlackHole(t)
	veryShortTimeout := time.Millisecond
	r := NewResolver(veryShortTimeout, addr)
	if ResolveDomain(context.Background(), r, "example.com.", veryShortTimeout, false) {
		t.Errorf("expected timeout against a black-holed resolver")
	}
}

func TestResolveDomainWithRetry(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"example.com": {A: "192.0.2.1"},
	})
	timeout := time.Second
	r := srv.Resolver(timeout)

	records, result := ResolveDomainWithRetry(context.Background(), r, "example.com.", timeout, false, 3, []string{"A"})
	if result != OutcomeFound {
		t.Errorf("expected example.com to resolve, got %v", result)
	}
	if len(records) == 0 {
		t.Errorf("expected records, got none")
	}

	_, result = ResolveDomainWithRetry(context.Background(), r, "missing.example.com.", timeout, false, 2, []string{"A"})
	if result == OutcomeFound {
		t.Errorf("expected missing name to fail")
	}
}

func TestResolveDomainWithRetryContextCancellation(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{"example.com": {A: "192.0.2.1"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	timeout := time.Second
	start := time.Now()
	_, result := ResolveDomainWithRetry(ctx, srv.Resolver(timeout), "example.com.", timeout, false, 5, []string{"A"})
	elapsed := time.Since(start)

	if result == OutcomeFound {
		t.Errorf("expected cancelled context to prevent resolution")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("expected near-instant return on cancelled context, took %s", elapsed)
	}
}

func TestCheckWildcard(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"www.example.com": {A: "192.0.2.1"},
	})
	timeout := time.Second
	isWildcard, _, err := CheckWildcard(context.Background(), srv.Resolver(timeout), "example.com", timeout)
	if err != nil {
		t.Fatalf("CheckWildcard returned error: %v", err)
	}
	if isWildcard {
		t.Errorf("expected example.com not to be a wildcard")
	}
}

func TestCheckWildcardCancelled(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := CheckWildcard(ctx, srv.Resolver(time.Second), "example.com", time.Second)
	if err == nil {
		t.Errorf("expected error from cancelled context")
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Outcome
	}{
		{name: "nil", err: nil, want: OutcomeFound},
		{
			name: "nxdomain",
			err:  &net.DNSError{Err: "no such host", Name: "missing.example.com", IsNotFound: true},
			want: OutcomeNXDomain,
		},
		{
			name: "timeout",
			err:  &net.DNSError{Err: "i/o timeout", Name: "slow.example.com", IsTimeout: true},
			want: OutcomeTimeout,
		},
		{
			name: "refused",
			err:  &net.DNSError{Err: "server refused", Name: "blocked.example.com"},
			want: OutcomeRefused,
		},
		{
			name: "refused mixed case",
			err:  &net.DNSError{Err: "REFUSED"},
			want: OutcomeRefused,
		},
		{
			name: "other dns error",
			err:  &net.DNSError{Err: "server misbehaving", Name: "x.example.com"},
			want: OutcomeOther,
		},
		{
			name: "generic error",
			err:  fmt.Errorf("dial udp: connection refused"),
			want: OutcomeOther,
		},
		{
			name: "wrapped nxdomain",
			err:  fmt.Errorf("lookup: %w", &net.DNSError{Err: "no such host", IsNotFound: true}),
			want: OutcomeNXDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.err); got != tt.want {
				t.Errorf("Classify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveDomainWithRetryNXDomainNoRetry(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{})
	_, outcome := ResolveDomainWithRetry(context.Background(), srv.Resolver(time.Second), "nope.example.com.", time.Second, false, 3, []string{"A"})
	if outcome != OutcomeNXDomain {
		t.Fatalf("outcome = %v, want NXDomain", outcome)
	}
	if got := srv.Queries(); got != 1 {
		t.Fatalf("queries = %d, want 1 (NXDOMAIN must not be retried)", got)
	}
}

func TestCheckWildcardFingerprint(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"*": {A: "192.0.2.99"},
	})
	is, fp, err := CheckWildcard(context.Background(), srv.Resolver(time.Second), "example.com", time.Second)
	if err != nil {
		t.Fatalf("CheckWildcard: %v", err)
	}
	if !is {
		t.Fatal("expected wildcard")
	}
	foundIP := false
	for _, r := range fp {
		if r.Type == "A" && r.Value == "192.0.2.99" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("fingerprint %v missing A 192.0.2.99", fp)
	}
}

func TestResolveTypesTCPFallbackOnTruncation(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"big.example.com": {A: "192.0.2.1", Truncated: true},
	})
	recs, _, err := ResolveTypes(context.Background(), srv.Resolver(2*time.Second), "big.example.com.", 2*time.Second, []string{"A"})
	if err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}
	if len(recs) != 1 || recs[0].Type != "A" || recs[0].Value != "192.0.2.1" {
		t.Fatalf("records = %v, want A 192.0.2.1", recs)
	}
	if srv.Queries() < 2 {
		t.Fatalf("queries = %d, want UDP then TCP", srv.Queries())
	}
}

func TestLiveResolverSmoke(t *testing.T) {
	if os.Getenv("SUBENUM_NETWORK_TESTS") != "1" {
		t.Skip("set SUBENUM_NETWORK_TESTS=1 to enable live resolver smoke test")
	}
	timeout := 3 * time.Second
	r := NewResolver(timeout, "8.8.8.8:53")
	if !ResolveDomain(context.Background(), r, "example.com.", timeout, false) {
		t.Fatal("expected example.com to resolve via 8.8.8.8")
	}
}
