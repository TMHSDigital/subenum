package dns

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestResolveDomain(t *testing.T) {
	timeout := time.Second * 2

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "Known existing domain",
			domain:   "google.com",
			expected: true,
		},
		{
			name:     "Known existing subdomain",
			domain:   "www.google.com",
			expected: true,
		},
		{
			name:     "Likely non-existent domain",
			domain:   "this-domain-should-not-exist-123456789.com",
			expected: false,
		},
		{
			name:     "Likely non-existent subdomain of valid domain",
			domain:   "this-subdomain-should-not-exist-123456789.google.com",
			expected: false,
		},
		{
			name:     "Empty domain",
			domain:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveDomain(context.Background(), tt.domain, timeout, "8.8.8.8:53", false)

			if got != tt.expected {
				t.Errorf("ResolveDomain(%q) = %v, want %v (may be network-dependent)",
					tt.domain, got, tt.expected)
			}
		})
	}
}

func TestResolveDomainTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	veryShortTimeout := time.Millisecond * 1

	result := ResolveDomain(context.Background(), "google.com", veryShortTimeout, "8.8.8.8:53", false)

	if result {
		t.Errorf("Expected timeout with 1ms deadline, but resolution succeeded")
	}
}

func TestResolveDomainWithCustomDNS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping custom DNS test in short mode")
	}

	timeout := time.Second * 2

	dnsServers := []string{
		"8.8.8.8:53",
		"1.1.1.1:53",
	}

	testDomain := "google.com"

	for _, server := range dnsServers {
		t.Run(fmt.Sprintf("DNS_Server_%s", server), func(t *testing.T) {
			result := ResolveDomain(context.Background(), testDomain, timeout, server, false)

			if !result {
				t.Errorf("Expected %s to resolve using DNS server %s, but it failed", testDomain, server)
			}
		})
	}
}

func TestResolveDomainWithRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping retry test in short mode")
	}

	timeout := time.Second * 2

	result := ResolveDomainWithRetry(context.Background(), "google.com", timeout, "8.8.8.8:53", false, 3)
	if !result {
		t.Errorf("Expected google.com to resolve with retries, but it failed")
	}

	result = ResolveDomainWithRetry(context.Background(), "this-domain-should-not-exist-123456789.com", timeout, "8.8.8.8:53", false, 2)
	if result {
		t.Errorf("Expected non-existent domain to fail even with retries")
	}
}

func TestResolveDomainWithRetryContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping context cancellation test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	timeout := time.Second * 2
	start := time.Now()
	result := ResolveDomainWithRetry(ctx, "google.com", timeout, "8.8.8.8:53", false, 5)
	elapsed := time.Since(start)

	if result {
		t.Errorf("Expected cancelled context to prevent resolution, but got true")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Expected near-instant return on cancelled context, took %s", elapsed)
	}
}

func TestCheckWildcard(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping wildcard detection test in short mode")
	}

	timeout := time.Second * 3

	isWildcard, err := CheckWildcard(context.Background(), "google.com", timeout, "8.8.8.8:53")
	if err != nil {
		t.Fatalf("CheckWildcard returned error: %v", err)
	}
	if isWildcard {
		t.Errorf("Expected google.com to NOT be a wildcard domain")
	}
}

func TestCheckWildcardCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := CheckWildcard(ctx, "example.com", time.Second, "8.8.8.8:53")
	if err == nil {
		t.Errorf("Expected error from cancelled context")
	}
}
