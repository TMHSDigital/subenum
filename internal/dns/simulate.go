package dns

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

// seededRand is a package-level random source seeded at startup.
// math/rand is appropriate here — simulation output is not security-sensitive.
var seededRand = rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec

// SimulateResolution returns a synthetic DNS result without performing any
// network I/O. Common subdomain prefixes resolve ~90% of the time; everything
// else uses the supplied hitRate (0-100).
func SimulateResolution(domain string, hitRate int, verbose bool) bool {
	commonSubdomains := []string{
		"www", "mail", "ftp", "blog",
		"api", "dev", "staging", "test",
		"admin", "portal", "app", "secure",
	}

	for _, sub := range commonSubdomains {
		if strings.HasPrefix(domain, sub+".") {
			if verbose {
				fakeTiming := time.Duration(50+seededRand.Intn(200)) * time.Millisecond
				fakeIP := fmt.Sprintf("192.168.%d.%d", seededRand.Intn(255), 1+seededRand.Intn(254))
				fmt.Fprintf(os.Stderr, "Resolved (SIMULATED): %s (IP: %s) in %s\n", domain, fakeIP, fakeTiming)
			}
			return seededRand.Intn(100) < 90
		}
	}

	result := seededRand.Intn(100) < hitRate

	if verbose {
		fakeTiming := time.Duration(100+seededRand.Intn(500)) * time.Millisecond
		if result {
			fakeIP := fmt.Sprintf("10.%d.%d.%d", seededRand.Intn(255), seededRand.Intn(255), 1+seededRand.Intn(254))
			fmt.Fprintf(os.Stderr, "Resolved (SIMULATED): %s (IP: %s) in %s\n", domain, fakeIP, fakeTiming)
		} else {
			fmt.Fprintf(os.Stderr, "Failed to resolve (SIMULATED): %s (Error: no such host) in %s\n", domain, fakeTiming)
		}
	}

	return result
}
