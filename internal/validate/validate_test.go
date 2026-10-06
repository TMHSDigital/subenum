package validate

import (
	"fmt"
	"strings"
	"testing"
)

func TestDNSServer(t *testing.T) {
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
			if err := DNSServer(server); err != nil {
				t.Errorf("DNSServer(%q) returned error: %v", server, err)
			}
		})
	}

	for _, tc := range invalidServers {
		t.Run(fmt.Sprintf("invalid_%s_%s", tc.server, tc.reason), func(t *testing.T) {
			if err := DNSServer(tc.server); err == nil {
				t.Errorf("DNSServer(%q) should have returned error (%s)", tc.server, tc.reason)
			}
		})
	}
}

func TestDomain(t *testing.T) {
	validDomains := []string{
		"example.com",
		"sub.example.com",
		"a.b.c.example.com",
		"test-domain.co.uk",
		"example.xn--p1ai",
		strings.Repeat("a", 63) + ".com",
	}

	invalidDomains := []string{
		"",
		"-example.com",
		"example-.com",
		".example.com",
		"example..com",
		strings.Repeat("a", 254) + ".com",
		strings.Repeat("a", 64) + ".com",
	}

	for _, domain := range validDomains {
		t.Run(fmt.Sprintf("valid_%s", domain), func(t *testing.T) {
			if err := Domain(domain); err != nil {
				t.Errorf("Domain(%q) returned error: %v", domain, err)
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
			if err := Domain(domain); err == nil {
				t.Errorf("Domain(%q) should have returned error", domain)
			}
		})
	}
}

// TestNormalizeDomain covers #54: every common way of writing a target
// normalizes to the same canonical domain.
func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		in, want string
		notes    int
		wantErr  string
	}{
		{in: "example.com", want: "example.com"},
		{in: "  Example.COM.  ", want: "example.com"},
		{in: "https://example.com/", want: "example.com", notes: 1},
		{in: "HTTPS://Example.com:8443/login?x=1", want: "example.com", notes: 1},
		{in: "example.com/path", want: "example.com", notes: 1},
		{in: "example.com:443", want: "example.com", notes: 1},
		{in: "*.example.com", want: "example.com", notes: 1},
		{in: "bücher.de", want: "xn--bcher-kva.de", notes: 1},
		{in: "_dmarc.example.com", want: "_dmarc.example.com"},
		{in: "user@example.com", wantErr: "email address"},
		{in: "https:///nohost", wantErr: "no host"},
		{in: "localhost", wantErr: "invalid domain format"},
		{in: "", wantErr: "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, notes, err := NormalizeDomain(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if len(notes) != tt.notes {
				t.Errorf("notes = %q, want %d", notes, tt.notes)
			}
		})
	}
}

// TestDNSServerTransports covers #86: DoT and DoH servers are accepted.
func TestDNSServerTransports(t *testing.T) {
	for _, ok := range []string{"tls://1.1.1.1", "tls://1.1.1.1:853", "tls://dns.google", "https://cloudflare-dns.com/dns-query", "https://1.1.1.1/dns-query",
		"tls://[::1]", "tls://[2606:4700::1111]", "tls://[::1]:853", "tls://::1"} {
		if err := DNSServer(ok); err != nil {
			t.Errorf("DNSServer(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"tls://", "tls://1.1.1.1:99999", "https://", "quic://1.1.1.1", "tls://bad host"} {
		if err := DNSServer(bad); err == nil {
			t.Errorf("DNSServer(%q) accepted", bad)
		}
	}
}

// TestDoTAddress covers #115: bracketed IPv6 hosts without a port get 853,
// and the certificate is checked against the bare host.
func TestDoTAddress(t *testing.T) {
	for in, want := range map[string][2]string{
		"tls://1.1.1.1":           {"1.1.1.1:853", "1.1.1.1"},
		"tls://dns.google:8853":   {"dns.google:8853", "dns.google"},
		"tls://[::1]":             {"[::1]:853", "::1"},
		"tls://[2606:4700::1111]": {"[2606:4700::1111]:853", "2606:4700::1111"},
		"tls://[::1]:853":         {"[::1]:853", "::1"},
		"tls://::1":               {"[::1]:853", "::1"},
	} {
		hostport, host, err := DoTAddress(in)
		if err != nil || hostport != want[0] || host != want[1] {
			t.Errorf("DoTAddress(%q) = %q, %q, %v; want %q, %q", in, hostport, host, err, want[0], want[1])
		}
	}
}
