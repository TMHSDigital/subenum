package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
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
			got := resolveDomain(context.Background(), tt.domain, timeout, DefaultDNSServer, false)

			if got != tt.expected {
				t.Errorf("resolveDomain(%q) = %v, want %v (may be network-dependent)",
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

	result := resolveDomain(context.Background(), "google.com", veryShortTimeout, DefaultDNSServer, false)

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
			result := resolveDomain(context.Background(), testDomain, timeout, server, false)

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

	result := resolveDomainWithRetry(context.Background(), "google.com", timeout, DefaultDNSServer, false, 3)
	if !result {
		t.Errorf("Expected google.com to resolve with retries, but it failed")
	}

	result = resolveDomainWithRetry(context.Background(), "this-domain-should-not-exist-123456789.com", timeout, DefaultDNSServer, false, 2)
	if result {
		t.Errorf("Expected non-existent domain to fail even with retries")
	}
}

func TestResolveDomainWithRetryContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping context cancellation test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	timeout := time.Second * 2
	start := time.Now()
	result := resolveDomainWithRetry(ctx, "google.com", timeout, DefaultDNSServer, false, 5)
	elapsed := time.Since(start)

	if result {
		t.Errorf("Expected cancelled context to prevent resolution, but got true")
	}
	// Should return almost immediately, not wait for 5 retries
	if elapsed > 500*time.Millisecond {
		t.Errorf("Expected near-instant return on cancelled context, took %s", elapsed)
	}
}

func TestValidateDNSServer(t *testing.T) {
	validServers := []string{
		"8.8.8.8:53",
		"1.1.1.1:53",
		"192.168.1.1:53",
		"[2001:4860:4860::8888]:53",
	}

	invalidServers := []struct {
		server string
		reason string
	}{
		{"8.8.8.8", "missing port"},
		{":53", "missing IP"},
		{"localhost:53", "not a valid IP"},
		{"256.1.1.1:53", "invalid IP octet"},
		{"1.1.1.1:99999", "port out of range"},
		{"1.1.1.1:0", "port zero"},
		{"1.1.1.1:-1", "negative port"},
		{"not-an-ip:53", "hostname instead of IP"},
	}

	for _, server := range validServers {
		t.Run(fmt.Sprintf("valid_%s", server), func(t *testing.T) {
			if err := validateDNSServer(server); err != nil {
				t.Errorf("validateDNSServer(%q) returned error: %v", server, err)
			}
		})
	}

	for _, tc := range invalidServers {
		t.Run(fmt.Sprintf("invalid_%s_%s", tc.server, tc.reason), func(t *testing.T) {
			if err := validateDNSServer(tc.server); err == nil {
				t.Errorf("validateDNSServer(%q) should have returned error (%s)", tc.server, tc.reason)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	validDomains := []string{
		"example.com",
		"sub.example.com",
		"a.b.c.example.com",
		"test-domain.co.uk",
	}

	invalidDomains := []string{
		"",
		"-example.com",
		"example-.com",
		".example.com",
		"example..com",
		strings.Repeat("a", 254) + ".com",
	}

	for _, domain := range validDomains {
		t.Run(fmt.Sprintf("valid_%s", domain), func(t *testing.T) {
			if err := validateDomain(domain); err != nil {
				t.Errorf("validateDomain(%q) returned error: %v", domain, err)
			}
		})
	}

	for _, domain := range invalidDomains {
		name := domain
		if name == "" {
			name = "empty"
		}
		if len(name) > 50 {
			name = name[:50] + "..."
		}
		t.Run(fmt.Sprintf("invalid_%s", name), func(t *testing.T) {
			if err := validateDomain(domain); err == nil {
				t.Errorf("validateDomain(%q) should have returned error", domain)
			}
		})
	}
}

func TestSimulateResolution(t *testing.T) {
	// Use 500 runs to make the 90% hit-rate test statistically near-certain.
	runs := 500

	resolved := 0
	for i := 0; i < runs; i++ {
		if simulateResolution("www.example.com", 15, false) {
			resolved++
		}
	}
	if resolved == 0 {
		t.Errorf("Expected common subdomains to resolve in simulation, got 0/%d", runs)
	}

	resolved = 0
	for i := 0; i < runs; i++ {
		if simulateResolution("zzz-random-prefix.example.com", 0, false) {
			resolved++
		}
	}
	if resolved != 0 {
		t.Errorf("Expected 0%% hit rate to never resolve, got %d/%d", resolved, runs)
	}
}

func TestSanitizeLine(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"api", "api"},
		{"  api  ", "api"},
		{"\tmail\t", "mail"},
		{"", ""},
		{"   ", ""},
		{"\t\r\n", ""},
		{"www", "www"},
	}

	for _, tt := range tests {
		got := sanitizeLine(tt.in)
		if got != tt.want {
			t.Errorf("sanitizeLine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestOutputFileWriting(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "subenum-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	outWriter := bufio.NewWriter(tmpFile)

	domains := []string{"www.example.com", "api.example.com", "mail.example.com"}
	for _, d := range domains {
		if _, err := fmt.Fprintln(outWriter, d); err != nil {
			t.Fatalf("Failed to write domain %q to output file: %v", d, err)
		}
	}

	if err := outWriter.Flush(); err != nil {
		t.Fatalf("Failed to flush output file: %v", err)
	}
	tmpFile.Close()

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	for _, d := range domains {
		if !strings.Contains(string(content), d) {
			t.Errorf("Expected output file to contain %q\nGot:\n%s", d, content)
		}
	}
}
