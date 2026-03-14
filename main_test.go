package main

import (
	"fmt"
	"strings"
	"testing"
)

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

func TestResolveAttempts(t *testing.T) {
	if got := resolveAttempts(0, 0); got != 1 {
		t.Errorf("default: got %d, want 1", got)
	}
	if got := resolveAttempts(5, 0); got != 5 {
		t.Errorf("-attempts=5: got %d, want 5", got)
	}
}
