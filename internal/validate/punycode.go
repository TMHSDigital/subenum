package validate

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// idnaProfile maps a label the way a resolver's lookup does (UTS #46,
// nontransitional, so ß stays ß): NFC normalization, case and width folding,
// and a refusal of code points IDNA disallows (#435).
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.BidiRule())

// ToASCII converts a lowercased name to its punycode form, as NormalizeDomain
// does for targets; ASCII labels, including a "*" wildcard, pass through.
func ToASCII(name string) (string, error) { return toASCII(name) }

// toASCII converts a domain to its ASCII (A-label) form. Every label with
// non-ASCII characters goes through UTS #46 mapping and then Punycode: an NFD
// spelling (e + U+0301) gives the same xn-- label as the NFC one, and
// full-width letters fold to ASCII. ASCII labels are left alone, so
// underscore labels (_dmarc) and a "*" wildcard, which IDNA's STD3 rules
// refuse, still pass through.
func toASCII(domain string) (string, error) {
	labels := strings.Split(domain, ".")
	for i, label := range labels {
		if isASCII(label) {
			continue
		}
		if !utf8.ValidString(label) {
			return "", fmt.Errorf("label %q is not valid UTF-8", label)
		}
		enc, err := idnaProfile.ToASCII(label)
		if err != nil {
			return "", fmt.Errorf("label %q is not a valid internationalized name: %w", label, err)
		}
		labels[i] = enc
	}
	return strings.Join(labels, "."), nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
