package wordlist

import (
	"strings"
	"testing"
)

// FuzzNormalize: any line normalises without panicking, and an accepted
// entry is lowercase, has no surrounding space or trailing dot, and
// normalises to itself (#259).
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"www", " API. ", "dev.api", "#comment", "*.x", "a..b", strings.Repeat("a", 64), "xn--bcher-kva", "\xef\xbb\xbfwww"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		entry, ok := Normalize(line)
		if !ok {
			if entry != "" {
				t.Errorf("Normalize(%q) rejected the line but returned %q", line, entry)
			}
			return
		}
		if entry != strings.ToLower(entry) || entry != strings.TrimSpace(entry) || strings.HasSuffix(entry, ".") || entry == "" {
			t.Errorf("Normalize(%q) = %q, not a canonical entry", line, entry)
		}
		if again, ok := Normalize(entry); !ok || again != entry {
			t.Errorf("Normalize(%q) = %q, %v; want it to be stable", entry, again, ok)
		}
	})
}
