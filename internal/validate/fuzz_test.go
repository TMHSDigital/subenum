package validate

import "testing"

// FuzzNormalizeDomain: any input normalises or fails without panicking, and
// an accepted domain passes Domain and normalises to itself (#259). It found
// #281: a kept trailing dot and unmapped Unicode full stops.
func FuzzNormalizeDomain(f *testing.F) {
	for _, s := range []string{"example.com", " HTTPS://Example.COM:8443/path?q ", "*.example.com.", "bücher.example", "user@example.com", "[::1]:53", "a..b", "xn--bcher-kva.example", "example.com/#x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		domain, _, err := NormalizeDomain(input)
		if err != nil {
			return
		}
		if derr := Domain(domain); derr != nil {
			t.Errorf("NormalizeDomain(%q) = %q, which Domain rejects: %v", input, domain, derr)
		}
		if again, _, err := NormalizeDomain(domain); err != nil || again != domain {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want it to be stable", domain, again, err)
		}
	})
}
