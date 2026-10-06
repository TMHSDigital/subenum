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
	"strings"

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

// generate returns the wordlist in a stable order: common prefixes, then
// domain terms, then each -combine prefix followed by its prefix-word
// combinations. Duplicates keep their first position, so the same options
// always produce byte-identical output.
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

// parseInterspersed parses flags that appear anywhere in args. The standard flag
// package stops at the first non-flag argument, which silently dropped every flag
// written after the domain (#29). Arguments after a "--" terminator are all
// treated as positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		before := len(args)
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positionals, nil
		}
		consumed := args[:before-len(rest)]
		if endsWithTerminator(fs, consumed) {
			return append(positionals, rest...), nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}

// endsWithTerminator reports whether the parsed arguments ended at a "--"
// terminator, as opposed to "--" being the value of a flag such as "-o --".
func endsWithTerminator(fs *flag.FlagSet, consumed []string) bool {
	n := len(consumed)
	if n == 0 || consumed[n-1] != "--" {
		return false
	}
	if n < 2 {
		return true
	}
	prev := consumed[n-2]
	if !strings.HasPrefix(prev, "-") || strings.Contains(prev, "=") {
		return true
	}
	fl := fs.Lookup(strings.TrimLeft(prev, "-"))
	if fl == nil {
		return true
	}
	if b, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
		return true // bool flags take no separate value
	}
	return false // "--" was the value of the preceding flag
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

	positionals, err := parseInterspersed(fs, args)
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

	words := generate(options{common: *addCommon, domain: *domainInfo, combine: *combineWith})
	if len(words) == 0 {
		_, _ = fmt.Fprintln(stderr, "Error: no entries generated; enable -common or pass -domain or -combine")
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
