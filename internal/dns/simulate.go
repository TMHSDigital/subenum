package dns

import (
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"time"
)

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
				fakeTiming := time.Duration(50+rand.IntN(200)) * time.Millisecond
				fakeIP := fmt.Sprintf("192.168.%d.%d", rand.IntN(255), 1+rand.IntN(254))
				fmt.Fprintf(os.Stderr, "Resolved (SIMULATED): %s (IP: %s) in %s\n", domain, fakeIP, fakeTiming)
			}
			return rand.IntN(100) < 90
		}
	}

	result := rand.IntN(100) < hitRate

	if verbose {
		fakeTiming := time.Duration(100+rand.IntN(500)) * time.Millisecond
		if result {
			fakeIP := fmt.Sprintf("10.%d.%d.%d", rand.IntN(255), rand.IntN(255), 1+rand.IntN(254))
			fmt.Fprintf(os.Stderr, "Resolved (SIMULATED): %s (IP: %s) in %s\n", domain, fakeIP, fakeTiming)
		} else {
			fmt.Fprintf(os.Stderr, "Failed to resolve (SIMULATED): %s (Error: no such host) in %s\n", domain, fakeTiming)
		}
	}

	return result
}
