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
	_, ok := SimulateResolve(domain, hitRate, verbose)
	return ok
}

// SimulateResolve is like SimulateResolution but also returns synthetic A
// records when the domain "resolves".
func SimulateResolve(domain string, hitRate int, verbose bool) ([]Record, bool) {
	commonSubdomains := []string{
		"www", "mail", "ftp", "blog",
		"api", "dev", "staging", "test",
		"admin", "portal", "app", "secure",
	}

	for _, sub := range commonSubdomains {
		if strings.HasPrefix(domain, sub+".") {
			if rand.IntN(100) < 90 {
				return synthResolved(domain, verbose)
			}
			return synthFailed(domain, verbose)
		}
	}

	if rand.IntN(100) < hitRate {
		return synthResolved(domain, verbose)
	}
	return synthFailed(domain, verbose)
}

func synthResolved(domain string, verbose bool) ([]Record, bool) {
	records := []Record{
		{Type: "A", Value: fmt.Sprintf("10.%d.%d.%d", rand.IntN(255), rand.IntN(255), 1+rand.IntN(254))},
	}
	if verbose {
		fakeTiming := time.Duration(50+rand.IntN(450)) * time.Millisecond
		fmt.Fprintf(os.Stderr, "Resolved (SIMULATED): %s (%s: %s) in %s\n", domain, records[0].Type, records[0].Value, fakeTiming)
	}
	return records, true
}

func synthFailed(domain string, verbose bool) ([]Record, bool) {
	if verbose {
		fakeTiming := time.Duration(100+rand.IntN(500)) * time.Millisecond
		fmt.Fprintf(os.Stderr, "Failed to resolve (SIMULATED): %s (Error: no such host) in %s\n", domain, fakeTiming)
	}
	return nil, false
}
