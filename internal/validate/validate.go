// Package validate holds input validators shared by the CLI and the TUI so the
// two entry points enforce identical domain and DNS server rules.
package validate

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// DefaultDNSServer is the resolver used when none is given; the CLI, the TUI
// and the DNS server error message all use this one constant (#80).
const DefaultDNSServer = "8.8.8.8:53"

var (
	labelRegex = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$`)
	tldRegex   = regexp.MustCompile(`^([a-zA-Z]{2,}|xn--[a-zA-Z0-9-]{1,59})$`)
)

// DNSServer checks that server is a valid ip:port address with an IP host and a
// port in the range 1-65535.
func DNSServer(server string) error {
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return fmt.Errorf("invalid format, expected ip:port (e.g., %s): %w", DefaultDNSServer, err)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("invalid IP address: %s", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %s (must be 1-65535)", portStr)
	}
	return nil
}

// NormalizeDomain turns a target as users type or paste it into the canonical
// form every entry point scans: trimmed, lowercase, no trailing dot, IDNs in
// punycode. It also strips a URL scheme and path, a :port and a leading "*.",
// returning a one-line note for each so the caller can say what it did (#54).
// The result is checked with Domain.
func NormalizeDomain(input string) (domain string, notes []string, err error) {
	s := strings.TrimSpace(input)
	if strings.Contains(s, "@") {
		return "", nil, fmt.Errorf("%q looks like an email address; pass just the domain", input)
	}
	if i := strings.Index(s, "://"); i >= 0 {
		u, perr := url.Parse(s)
		if perr != nil || u.Hostname() == "" {
			return "", nil, fmt.Errorf("%q looks like a URL but has no host; pass just the domain", input)
		}
		s = u.Hostname()
		notes = append(notes, fmt.Sprintf("%q looks like a URL; scanning host %s", input, s))
	} else if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
		notes = append(notes, fmt.Sprintf("ignoring the path in %q; scanning host %s", input, s))
	}
	if host, port, serr := net.SplitHostPort(s); serr == nil {
		if _, perr := strconv.Atoi(port); perr == nil {
			s = host
			notes = append(notes, fmt.Sprintf("ignoring port %s; DNS enumeration has no ports", port))
		}
	}
	if strings.HasPrefix(s, "*.") {
		s = s[2:]
		notes = append(notes, fmt.Sprintf("ignoring the leading *. wildcard; scanning %s", s))
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if !isASCII(s) {
		ascii, ierr := toASCII(s)
		if ierr != nil {
			return "", nil, fmt.Errorf("invalid internationalized domain %q: %w", input, ierr)
		}
		notes = append(notes, fmt.Sprintf("using the punycode form %s for %s", ascii, s))
		s = ascii
	}
	if err := Domain(s); err != nil {
		return "", nil, err
	}
	return s, notes, nil
}

// Domain checks that domain is non-empty, within the 253-character limit, and
// conforms to DNS naming rules: 1-63 characters per label, and a TLD that is
// either alphabetic (2+) or a punycode xn-- prefix. Labels other than the TLD
// may contain underscores (_dmarc, _domainkey), as wordlist entries can.
func Domain(domain string) error {
	if len(domain) == 0 {
		return fmt.Errorf("domain cannot be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain exceeds maximum length of 253 characters")
	}
	normalized := strings.ToLower(strings.TrimSuffix(domain, "."))
	labels := strings.Split(normalized, ".")
	if len(labels) < 2 {
		return fmt.Errorf("invalid domain format: %s", domain)
	}
	for i, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("invalid domain label length in %s", domain)
		}
		if i == len(labels)-1 {
			if !tldRegex.MatchString(label) {
				return fmt.Errorf("invalid domain format: %s", domain)
			}
			continue
		}
		if !labelRegex.MatchString(label) {
			return fmt.Errorf("invalid domain format: %s", domain)
		}
	}
	return nil
}
