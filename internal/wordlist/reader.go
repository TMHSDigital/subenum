package wordlist

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// labelRegex accepts one DNS label of 1-63 characters: letters, digits,
// hyphens (not at either end) and underscores, so service labels such as
// _dmarc or _domainkey are kept.
var labelRegex = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// maxNameLen is the longest presentation-format domain name (RFC 1035).
const maxNameLen = 253

// SanitizeLine trims whitespace from a wordlist entry.
// Returns an empty string for blank or whitespace-only lines.
func SanitizeLine(s string) string {
	return strings.TrimSpace(s)
}

// Normalize turns a raw wordlist line into the prefix that will be queried. It
// returns ok=false for lines that must not become queries: blank lines, #
// comments, and entries that are not valid DNS labels (whitespace, wildcards,
// empty or over-long labels). Multi-label prefixes such as "dev.api" are kept.
// Entries are lowercased so case variants deduplicate.
func Normalize(line string) (entry string, ok bool) {
	entry = strings.ToLower(SanitizeLine(line))
	entry = strings.TrimSuffix(entry, ".")
	if entry == "" || strings.HasPrefix(entry, "#") {
		return "", false
	}
	for _, label := range strings.Split(entry, ".") {
		if !labelRegex.MatchString(label) {
			return "", false
		}
	}
	return entry, true
}

// isComment reports whether a line is blank or a # comment, which are skipped
// silently rather than counted as invalid.
func isComment(line string) bool {
	s := SanitizeLine(line)
	return s == "" || strings.HasPrefix(s, "#")
}

// LoadWordlist reads a wordlist file into a normalized, deduplicated slice,
// preserving first-occurrence order. Blank lines and # comments are ignored.
// Invalid entries, and entries whose full name under domain would exceed 253
// characters, are counted in skipped. duplicates counts case-insensitive
// repeats.
func LoadWordlist(path, domain string) (entries []string, duplicates, skipped int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = f.Close() }()

	apexLen := len(strings.TrimSuffix(domain, "."))
	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if isComment(line) {
			continue
		}
		entry, ok := Normalize(line)
		if !ok || len(entry)+1+apexLen > maxNameLen {
			skipped++
			continue
		}
		if _, exists := seen[entry]; exists {
			duplicates++
			continue
		}
		seen[entry] = struct{}{}
		entries = append(entries, entry)
	}
	return entries, duplicates, skipped, scanner.Err()
}
