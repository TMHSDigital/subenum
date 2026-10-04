package dns

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

// SimulateResolve returns a synthetic DNS result without performing any network
// I/O, along with synthetic records for the requested types when the domain
// "resolves". Common subdomain prefixes resolve ~90% of the time; everything
// else uses the supplied hitRate (0-100).
func SimulateResolve(domain string, hitRate int, logf Logf, types []string) ([]Record, bool) {
	commonSubdomains := []string{
		"www", "mail", "ftp", "blog",
		"api", "dev", "staging", "test",
		"admin", "portal", "app", "secure",
	}

	for _, sub := range commonSubdomains {
		if strings.HasPrefix(domain, sub+".") {
			if rand.IntN(100) < 90 {
				return synthResolved(domain, types, logf)
			}
			return synthFailed(domain, logf)
		}
	}

	if rand.IntN(100) < hitRate {
		return synthResolved(domain, types, logf)
	}
	return synthFailed(domain, logf)
}

func synthResolved(domain string, types []string, logf Logf) ([]Record, bool) {
	if len(types) == 0 {
		types = DefaultTypes
	}
	var records []Record
	for _, t := range types {
		switch t {
		case "A":
			records = append(records, Record{Type: "A", Value: fmt.Sprintf("10.%d.%d.%d", rand.IntN(255), rand.IntN(255), 1+rand.IntN(254))})
		case "AAAA":
			records = append(records, Record{Type: "AAAA", Value: fmt.Sprintf("2001:db8::%x", rand.IntN(65535))})
		case "CNAME":
			records = append(records, Record{Type: "CNAME", Value: "target." + domain})
		}
	}
	if len(records) == 0 {
		return nil, false
	}
	if logf != nil {
		fakeTiming := time.Duration(50+rand.IntN(450)) * time.Millisecond
		logf("Resolved (SIMULATED): %s (%s: %s) in %s", domain, records[0].Type, records[0].Value, fakeTiming)
	}
	return records, true
}

func synthFailed(domain string, logf Logf) ([]Record, bool) {
	if logf != nil {
		fakeTiming := time.Duration(100+rand.IntN(500)) * time.Millisecond
		logf("Failed to resolve (SIMULATED): %s (Error: no such host) in %s", domain, fakeTiming)
	}
	return nil, false
}
