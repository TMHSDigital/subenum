package validate

import (
	"strings"
	"testing"
)

// Code points spelled out by value, so the source shows what each test uses.
var (
	combiningAcute = string(rune(0x0301)) // NFD: "e" + this is "é"
	c1Control      = string(rune(0x0080))
	leftToRight    = string(rune(0x200E)) // a bidi format mark
)

// TestToASCII checks the conversion against known A-labels, including the
// RFC 3492 section 7.1 sample (B) Chinese (simplified), and the UTS #46
// mapping (#435): NFD and NFC spellings agree, full-width letters fold to
// ASCII, and ASCII labels IDNA would refuse (_dmarc, *) pass through.
func TestToASCII(t *testing.T) {
	for in, want := range map[string]string{
		"bücher.de":                          "xn--bcher-kva.de",
		"münchen.de":                         "xn--mnchen-3ya.de",
		"例え.jp":                              "xn--r8jz45g.jp",
		"他们为什么不说中文":                          "xn--ihqwcrb4cv8a8dqg056pqjye",
		"straße.example":                     "xn--strae-oqa.example",
		"www.bücher.de":                      "www.xn--bcher-kva.de",
		"plain.example":                      "plain.example",
		"café.example":                       "xn--caf-dma.example", // NFC
		"cafe" + combiningAcute + ".example": "xn--caf-dma.example", // NFD
		"ｅｘａｍｐｌｅ.com":                        "example.com",
		"_dmarc.bücher.de":                   "_dmarc.xn--bcher-kva.de",
		"*.bücher.de":                        "*.xn--bcher-kva.de",
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

// TestNormalizeDomainIDNMapping covers #435 end to end: a decomposed or
// full-width target scans the registered name, and a disallowed code point
// is a clear error rather than a scan of a name that cannot exist.
func TestNormalizeDomainIDNMapping(t *testing.T) {
	for in, want := range map[string]string{
		"Cafe" + combiningAcute + ".Example": "xn--caf-dma.example",
		"ｅｘａｍｐｌｅ.com":                        "example.com",
	} {
		got, _, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"bad" + c1Control + "name.example", "a" + leftToRight + "b.example"} {
		_, _, err := NormalizeDomain(in)
		if err == nil || !strings.Contains(err.Error(), "internationalized") {
			t.Errorf("NormalizeDomain(%q) error = %v, want an internationalized-domain error", in, err)
		}
	}
}
