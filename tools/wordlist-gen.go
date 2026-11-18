// Copyright (c) 2026 TM Hospitality Strategies
//
// Tool for generating custom wordlists for subdomain enumeration.
// For authorized use only.

// Command wordlist-gen generates a custom subdomain wordlist from common
// prefixes, terms taken from a domain name, and prefix combinations.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/TMHSDigital/subenum/internal/cliargs"
	"github.com/TMHSDigital/subenum/internal/diff"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// commonPrefixes are frequently seen subdomain labels, emitted first when
// -common is set.
var commonPrefixes = []string{
	"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
	"smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
	"portal", "admin", "host", "api", "dev", "web", "cloud", "email",
	"apps", "support", "app", "staging", "proxy", "beta", "gateway",
	"cdn", "auth", "intranet", "mobile", "sso", "help", "docs",
}

// secondLevelSuffixes are labels that sit under a ccTLD as a registry
// namespace (acme.co.uk, acme.com.au), so they are stripped along with it.
var secondLevelSuffixes = map[string]bool{
	"co": true, "com": true, "net": true, "org": true, "gov": true,
	"edu": true, "ac": true, "or": true, "ne": true, "go": true,
}

type options struct {
	common  bool
	domain  string
	combine string
	learned []string // labels from earlier results (-from), most frequent first
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(s string) error { *l = append(*l, s); return nil }

// learnLabels reads earlier subenum results files, in any output format, and
// returns the labels of their names below each name's apex, most frequent
// first, then alphabetically (#423). The apex is domain when a name ends in
// it, and otherwise the registrable domain as domainTerms sees it: the last
// label, a second-level label such as "co", and the organisation's label.
// Labels seen fewer than minCount times are dropped.
func learnLabels(paths []string, domain string, minCount int) ([]string, error) {
	domain = strings.ToLower(strings.Trim(domain, "."))
	counts := map[string]int{}
	for _, path := range paths {
		b, err := diff.Load(path)
		if err != nil {
			return nil, fmt.Errorf("reading -from %s: %w", path, err)
		}
		for name := range b.Names {
			for _, label := range labelsBelowApex(name, domain) {
				counts[label]++
			}
		}
	}
	labels := make([]string, 0, len(counts))
	for label, n := range counts {
		if n >= minCount {
			labels = append(labels, label)
		}
	}
	sort.Slice(labels, func(i, j int) bool {
		if counts[labels[i]] != counts[labels[j]] {
			return counts[labels[i]] > counts[labels[j]]
		}
		return labels[i] < labels[j]
	})
	return labels, nil
}

// labelsBelowApex splits name into the labels left of its apex.
func labelsBelowApex(name, domain string) []string {
	if domain != "" && strings.HasSuffix(name, "."+domain) {
		return strings.Split(strings.TrimSuffix(name, "."+domain), ".")
	}
	labels := strings.Split(name, ".")
	apex := 2 // the organisation's label and the TLD
	if len(labels) > 2 && secondLevelSuffixes[labels[len(labels)-2]] {
		apex = 3
	}
	if len(labels) <= apex {
		return nil
	}
	return labels[:len(labels)-apex]
}

// domainTerms extracts candidate words from a domain: the public suffix is
// dropped (the last label, plus a second-level label such as "co" in
// acme.co.uk) and the rest is split on dots, hyphens and underscores. Terms
// shorter than three characters are skipped.
func domainTerms(domain string) []string {
	labels := strings.Split(strings.ToLower(strings.Trim(domain, ".")), ".")
	if len(labels) > 1 {
		labels = labels[:len(labels)-1]
	}
	if len(labels) > 1 && secondLevelSuffixes[labels[len(labels)-1]] {
		labels = labels[:len(labels)-1]
	}
	var terms []string
	for _, part := range strings.FieldsFunc(strings.Join(labels, "."), func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	}) {
		if len(part) > 2 {
			terms = append(terms, part)
		}
	}
	return terms
}

// generate returns the wordlist in a stable order: labels learned from
// earlier results, then common prefixes, then domain terms, then each
// -combine prefix followed by its prefix-word combinations. Duplicates keep
// their first position, so the same options always produce byte-identical
// output.
func generate(o options) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(w string) {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" || seen[w] {
			return
		}
		// Only valid labels: a too-long combination or an odd domain term
		// would be skipped by subenum anyway.
		if _, ok := wordlist.Normalize(w); !ok {
			return
		}
		seen[w] = true
		out = append(out, w)
	}

	for _, l := range o.learned {
		add(l)
	}
	if o.common {
		for _, p := range commonPrefixes {
			add(p)
		}
	}
	if o.domain != "" {
		for _, t := range domainTerms(o.domain) {
			add(t)
		}
	}
	if o.combine != "" {
		base := append([]string(nil), out...)
		for _, prefix := range strings.Split(o.combine, ",") {
			prefix = strings.ToLower(strings.TrimSpace(prefix))
			if prefix == "" {
				continue
			}
			add(prefix)
			for _, word := range base {
				if word != prefix { // no "shop-shop"
					add(prefix + "-" + word)
				}
			}
		}
	}
	return out
}

// writeWordlist writes one word per line and reports the first write error.
func writeWordlist(w io.Writer, words []string) error {
	bw := bufio.NewWriter(w)
	for _, word := range words {
		if _, err := fmt.Fprintln(bw, word); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// validateCombine rejects -combine prefixes that are not valid DNS labels,
// which subenum would otherwise skip silently when it loads the list (#59).
func validateCombine(combine string) error {
	for _, prefix := range strings.Split(combine, ",") {
		p := strings.TrimSpace(prefix)
		if p == "" {
			continue
		}
		if _, ok := wordlist.Normalize(p); !ok || strings.Contains(p, ".") {
			return fmt.Errorf("invalid -combine prefix %q: use letters, digits, hyphens or underscores", p)
		}
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wordlist-gen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outputFile := fs.String("o", "wordlist.txt", "Path to output wordlist file")
	force := fs.Bool("f", false, "Overwrite the output file if it already exists")
	combineWith := fs.String("combine", "", "Combine each word with these prefixes (comma-separated)")
	addCommon := fs.Bool("common", true, "Add common subdomain prefixes")
	domainInfo := fs.String("domain", "", "Domain to extract potential subdomains from (e.g., company-name.com -> company, name)")
	verbose := fs.Bool("v", false, "Print every generated entry")
	var from stringList
	fs.Var(&from, "from", "Earlier subenum results file (text, JSON, JSONL or CSV) to learn labels from, most frequent first; repeatable")
	minCount := fs.Int("min-count", 1, "With -from, drop labels seen fewer than this many times")

	positionals, err := cliargs.Parse(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	// If any positionals remain, that's a usage error
	if len(positionals) > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected argument %q; to take subdomains from a domain, pass -domain %s\n", positionals[0], positionals[0])
		return 2
	}

	if *outputFile == "" {
		_, _ = fmt.Fprintln(stderr, "Error: output file cannot be empty")
		return 2
	}
	if err := validateCombine(*combineWith); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	if *minCount < 1 {
		_, _ = fmt.Fprintf(stderr, "Error: -min-count must be at least 1, got %d\n", *minCount)
		return 2
	}
	learned, err := learnLabels(from, *domainInfo, *minCount)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	words := generate(options{common: *addCommon, domain: *domainInfo, combine: *combineWith, learned: learned})
	if len(words) == 0 {
		_, _ = fmt.Fprintln(stderr, "Error: no entries generated; enable -common or pass -domain, -combine or -from")
		return 1
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !*force {
		flags |= os.O_EXCL // never silently replace an existing wordlist (#59)
	}
	file, err := os.OpenFile(*outputFile, flags, 0o644) //nolint:gosec // a generated wordlist is not sensitive; same mode os.Create gives
	if errors.Is(err, os.ErrExist) {
		_, _ = fmt.Fprintf(stderr, "Error: %s already exists; pass -f to overwrite it or -o to choose another path\n", *outputFile)
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error creating output file: %v\n", err)
		return 1
	}
	writeErr := writeWordlist(file, words)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error writing %s: %v\n", *outputFile, firstErr(writeErr, closeErr))
		return 1
	}

	if *verbose {
		for _, w := range words {
			_, _ = fmt.Fprintln(stdout, w)
		}
	}
	_, _ = fmt.Fprintf(stderr, "Wordlist generated at %s with %d unique entries\n", *outputFile, len(words))
	_, _ = fmt.Fprintln(stderr, "NOTE: Only use this tool to generate wordlists for domains you have explicit permission to test.")
	return 0
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
