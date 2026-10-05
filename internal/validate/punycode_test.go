package validate

import "testing"

// TestToASCII checks the Punycode encoder against known A-labels, including
// the RFC 3492 section 7.1 sample (B) Chinese (simplified).
func TestToASCII(t *testing.T) {
	for in, want := range map[string]string{
		"bücher.de":      "xn--bcher-kva.de",
		"münchen.de":     "xn--mnchen-3ya.de",
		"例え.jp":          "xn--r8jz45g.jp",
		"他们为什么不说中文":      "xn--ihqwcrb4cv8a8dqg056pqjye",
		"straße.example": "xn--strae-oqa.example",
		"www.bücher.de":  "www.xn--bcher-kva.de",
		"plain.example":  "plain.example",
	} {
		got, err := toASCII(in)
		if err != nil {
			t.Fatalf("toASCII(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("toASCII(%q) = %q, want %q", in, got, want)
		}
	}
}
