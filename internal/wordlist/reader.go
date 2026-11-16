// Package wordlist reads wordlist files and normalizes their entries into
// the DNS labels a scan queries.
package wordlist

import (
	"bufio"
	"hash/maphash"
	"io"
	"math"
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
	counts  []uint32 // occurrences of each entry in the raw lines (#248: 4 bytes, not 8)
	invalid int      // lines that are not valid DNS labels
	maxLen  int      // longest entry
	dotted  int      // entries with more than one label, the only ones that can end in a target (#351)
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
	index *entryIndex
}

// NewPreparer returns an empty Preparer.
func NewPreparer() *Preparer {
	return &Preparer{p: &Prepared{}, index: newEntryIndex()}
}

// entryIndex finds an entry's position in Prepared.entries. It is an
// open-addressing hash table whose slots hold only a position plus one (0
// is an empty slot), and it compares against the entries themselves, so it
// costs about 5 to 11 bytes per entry where a map[string]int cost several
// times that: on a 5M-line list it was most of the load's peak memory (#248).
type entryIndex struct {
	seed  maphash.Seed
	slots []uint32
	bits  uint   // len(slots) is 1<<bits
	n     uint32 // occupied slots, which is also the next entry's position
}

const minIndexBits = 10

func newEntryIndex() *entryIndex {
	return &entryIndex{seed: maphash.MakeSeed(), slots: make([]uint32, 1<<minIndexBits), bits: minIndexBits}
}

// find returns entry's slot and position plus one, or its empty slot and 0
// when entries does not hold it.
func (x *entryIndex) find(entries []string, entry string) (slot uint64, pos uint32) {
	mask := uint64(1)<<x.bits - 1
	for slot = maphash.String(x.seed, entry) & mask; ; slot = (slot + 1) & mask {
		pos = x.slots[slot]
		if pos == 0 || entries[pos-1] == entry {
			return slot, pos
		}
	}
}

// add records that the entry just appended to entries belongs at slot, the
// empty slot find returned for it. The table doubles once it is 3/4 full,
// which keeps probe runs short while the table stays small.
func (x *entryIndex) add(entries []string, slot uint64) {
	if x.n == math.MaxUint32-1 {
		panic("wordlist: more than 4294967294 distinct entries")
	}
	x.n++
	x.slots[slot] = x.n
	if uint64(x.n)*4 <= uint64(3)<<x.bits {
		return
	}
	x.bits++
	mask := uint64(1)<<x.bits - 1
	slots := make([]uint32, 1<<x.bits)
	for _, pos := range x.slots {
		if pos == 0 {
			continue
		}
		s := maphash.String(x.seed, entries[pos-1]) & mask
		for slots[s] != 0 {
			s = (s + 1) & mask
		}
		slots[s] = pos
	}
	x.slots = slots
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
	slot, pos := pr.index.find(p.entries, entry)
	if pos != 0 {
		p.counts[pos-1]++
		return
	}
	p.entries = append(p.entries, entry)
	p.counts = append(p.counts, 1)
	p.maxLen = max(p.maxLen, len(entry))
	if strings.Contains(entry, ".") {
		p.dotted++
	}
	pr.index.add(p.entries, slot)
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
// is kept once and its repeats are duplicates. An entry that already ends in
// domain, such as a full name pasted from another tool, is used as the
// prefix in front of it, so "www.example.com" under example.com is www, not
// www.example.com.example.com (#351); it is a duplicate when that prefix is
// also in the list. The returned slice may be shared between calls;
// appending to it copies.
func (p *Prepared) For(domain string) (entries []string, duplicates, skipped int) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	limit := maxNameLen - 1 - len(domain)
	skipped = p.invalid
	suffix := p.targetSuffix(domain)
	if p.maxLen <= limit && suffix == "" {
		for _, c := range p.counts {
			duplicates += int(c) - 1
		}
		return p.entries[:len(p.entries):len(p.entries)], duplicates, skipped
	}
	// A stripped entry whose prefix the list also holds on its own is a
	// repeat of that entry, wherever the two appear.
	var plain, emitted map[string]bool
	if suffix != "" {
		plain, emitted = map[string]bool{}, map[string]bool{}
		for _, entry := range p.entries {
			if prefix, ok := strings.CutSuffix(entry, suffix); ok {
				plain[prefix] = false
			}
		}
		for _, entry := range p.entries {
			if _, ok := plain[entry]; ok {
				plain[entry] = true
			}
		}
	}
	for i, entry := range p.entries {
		if suffix != "" {
			if prefix, ok := strings.CutSuffix(entry, suffix); ok {
				if plain[prefix] || emitted[prefix] {
					duplicates += int(p.counts[i])
					continue
				}
				emitted[prefix] = true
				entry = prefix
			}
		}
		if len(entry) > limit {
			skipped += int(p.counts[i])
			continue
		}
		duplicates += int(p.counts[i]) - 1
		entries = append(entries, entry)
	}
	return entries, duplicates, skipped
}

// targetSuffix returns "."+domain when some entry ends in it, and "" when
// none does or domain is empty. domain is lower case without a final dot.
func (p *Prepared) targetSuffix(domain string) string {
	if domain == "" || p.dotted == 0 {
		return ""
	}
	suffix := "." + domain
	for _, entry := range p.entries {
		if strings.HasSuffix(entry, suffix) {
			return suffix
		}
	}
	return ""
}

// Suffixed reports how many distinct entries end in domain, which For uses
// as prefixes (#351), so a caller can say so once.
func (p *Prepared) Suffixed(domain string) int {
	suffix := p.targetSuffix(strings.ToLower(strings.TrimSuffix(domain, ".")))
	if suffix == "" {
		return 0
	}
	n := 0
	for _, entry := range p.entries {
		if strings.HasSuffix(entry, suffix) {
			n++
		}
	}
	return n
}

// NotIn returns the names that are not in entries, in their order and
// without repeats. The set it builds holds the names, not the entries, so
// checking a few source names or permutations against a large wordlist costs
// one pass over it and no map as large as it (#321).
func NotIn(names, entries []string) []string {
	if len(names) == 0 {
		return nil
	}
	left := make(map[string]struct{}, len(names))
	for _, n := range names {
		left[n] = struct{}{}
	}
	for _, e := range entries {
		if len(left) == 0 {
			return nil
		}
		delete(left, e)
	}
	var out []string
	for _, n := range names {
		if _, ok := left[n]; ok {
			delete(left, n)
			out = append(out, n)
		}
	}
	return out
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
