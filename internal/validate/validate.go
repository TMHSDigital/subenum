// Package validate holds input validators shared by the CLI and the TUI so the
// two entry points enforce identical domain and DNS server rules.
package validate

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
)

// exampleDNSServer is shown in the DNS server format error message.
const exampleDNSServer = "8.8.8.8:53"

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// DNSServer checks that server is a valid ip:port address with an IP host and a
// port in the range 1-65535.
func DNSServer(server string) error {
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return fmt.Errorf("invalid format, expected ip:port (e.g., %s): %w", exampleDNSServer, err)
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

// Domain checks that domain is non-empty, within the 253-character limit, and
// conforms to DNS naming rules.
func Domain(domain string) error {
	if len(domain) == 0 {
		return fmt.Errorf("domain cannot be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain exceeds maximum length of 253 characters")
	}
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}
	return nil
}
