// Package wordlist reads wordlist files and normalizes their entries into
// the DNS labels a scan queries.
package wordlist

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// validLabel accepts one lowercased DNS label of 1-63 characters: letters,
// digits, hyphens (not at either end) and underscores, so service labels such
// as _dmarc or _domainkey are kept. It is hand-rolled rather than a regexp
// because it runs once per label of every wordlist line (#182).
func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// maxNameLen is the longest presentation-format domain name (RFC 1035).
const maxNameLen = 253

// maxLineLen caps how much of one line is kept. Anything longer than
// maxNameLen can never become a query, so the rest is discarded unread.
const maxLineLen = 1024

// Stdin is the path that makes ReadLines read standard input.
const Stdin = "-"

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
	for rest := entry; ; {
		label, tail, more := strings.Cut(rest, ".")
		if !validLabel(label) {
			return "", false
		}
		if !more {
			return entry, true
		}
		rest = tail
	}
}

// IsComment reports whether a line is blank or a # comment, which are skipped
// silently rather than counted as invalid.
func IsComment(line string) bool {
	s := SanitizeLine(line)
	return s == "" || strings.HasPrefix(s, "#")
}

// ReadLines reads every line of path, or of standard input when path is "-".
func ReadLines(path string) ([]string, error) {
	var lines []string
	err := EachLineOf(path, func(line string) { lines = append(lines, line) })
	return lines, err
}

// EachLineOf calls fn with each line of path, or of standard input when
// path is "-", without holding the file in memory (#248).
func EachLineOf(path string, fn func(string)) error {
	if path == Stdin {
		return EachLine(os.Stdin, fn)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return EachLine(f, fn)
}

// ReadLinesFrom is ReadLines for an already open reader, such as the
// wordlist embedded in the binary.
func ReadLinesFrom(r io.Reader) ([]string, error) {
	var lines []string
	err := EachLine(r, func(line string) { lines = append(lines, line) })
	return lines, err
}

// EachLine calls fn with each line of r, as ReadLinesFrom would return it.
func EachLine(r io.Reader, fn func(string)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	first := true
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// A line longer than any valid name (a merged list gone wrong, a
		// binary file) is truncated and drained rather than failing the whole
		// run; Build then counts it as skipped (#56).
		line := string(chunk[:min(len(chunk), maxLineLen)])
		for isPrefix && err == nil {
			_, isPrefix, err = br.ReadLine()
		}
		if err != nil && err != io.EOF {
			return err
		}
		if first {
			// Windows editors often prepend a UTF-8 byte order mark, which
			// TrimSpace does not remove; it would invalidate the first entry.
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}
		fn(line)
		if err == io.EOF {
			return nil
		}
	}
}

// Build normalizes raw wordlist lines for one target domain, preserving
// first-occurrence order. Blank lines and # comments are ignored. Invalid
// entries, and entries whose full name under domain would exceed 253
// characters, are counted in skipped. duplicates counts case-insensitive
// repeats. To build one list for several domains, use Prepare and For.
func Build(lines []string, domain string) (entries []string, duplicates, skipped int) {
	return Prepare(lines).For(domain)
}

// Prepared is a wordlist normalized once, so a run over many target domains
// pays for normalization once and per target only for the name-length check
// (#182).
type Prepared struct {
	entries []string // valid, deduplicated, in first-occurrence order
	counts  []int    // occurrences of each entry in the raw lines
	invalid int      // lines that are not valid DNS labels
	maxLen  int      // longest entry
}

// Prepare normalizes raw wordlist lines; see Build.
func Prepare(lines []string) *Prepared {
	pr := NewPreparer()
	for _, line := range lines {
		pr.Add(line)
	}
	return pr.Prepared()
}

// Preparer builds a Prepared one line at a time, so a large wordlist can be
// normalized while it is read instead of first being held as raw lines
// (#248).
type Preparer struct {
	p     *Prepared
	index map[string]int
}

// NewPreparer returns an empty Preparer.
func NewPreparer() *Preparer {
	return &Preparer{p: &Prepared{}, index: make(map[string]int)}
}

// Add takes one raw wordlist line.
func (pr *Preparer) Add(line string) {
	if IsComment(line) {
		return
	}
	entry, ok := Normalize(line)
	p := pr.p
	if !ok {
		p.invalid++
		return
	}
	if i, exists := pr.index[entry]; exists {
		p.counts[i]++
		return
	}
	pr.index[entry] = len(p.entries)
	p.entries = append(p.entries, entry)
	p.counts = append(p.counts, 1)
	p.maxLen = max(p.maxLen, len(entry))
}

// Prepared returns the result and releases the Preparer's index; the
// Preparer must not be used afterwards.
func (pr *Preparer) Prepared() *Prepared {
	p := pr.p
	pr.p, pr.index = nil, nil
	return p
}

// For returns the entries for domain with the same counts Build gives: an
// entry too long for domain is skipped at every occurrence, any other entry
// is kept once and its repeats are duplicates. The returned slice may be
// shared between calls; appending to it copies.
func (p *Prepared) For(domain string) (entries []string, duplicates, skipped int) {
	limit := maxNameLen - 1 - len(strings.TrimSuffix(domain, "."))
	skipped = p.invalid
	if p.maxLen <= limit {
		for _, c := range p.counts {
			duplicates += c - 1
		}
		return p.entries[:len(p.entries):len(p.entries)], duplicates, skipped
	}
	for i, entry := range p.entries {
		if len(entry) > limit {
			skipped += p.counts[i]
			continue
		}
		duplicates += p.counts[i] - 1
		entries = append(entries, entry)
	}
	return entries, duplicates, skipped
}

// LoadWordlist reads a wordlist (path "-" means standard input) and builds it
// for domain; see Build.
func LoadWordlist(path, domain string) (entries []string, duplicates, skipped int, err error) {
	lines, err := ReadLines(path)
	if err != nil {
		return nil, 0, 0, err
	}
	entries, duplicates, skipped = Build(lines, domain)
	return entries, duplicates, skipped, nil
}
