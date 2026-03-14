package wordlist

import (
	"bufio"
	"os"
	"strings"
)

// SanitizeLine trims whitespace from a wordlist entry.
// Returns an empty string for blank or whitespace-only lines.
func SanitizeLine(s string) string {
	return strings.TrimSpace(s)
}

// LoadWordlist reads a wordlist file into a deduplicated slice, preserving
// first-occurrence order. It returns the entries, how many duplicates were
// removed, and any error from reading the file.
func LoadWordlist(path string) ([]string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()

	seen := make(map[string]struct{})
	var entries []string
	duplicates := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := SanitizeLine(scanner.Text())
		if line == "" {
			continue
		}
		if _, exists := seen[line]; exists {
			duplicates++
			continue
		}
		seen[line] = struct{}{}
		entries = append(entries, line)
	}
	if err := scanner.Err(); err != nil {
		return entries, duplicates, err
	}
	return entries, duplicates, nil
}
