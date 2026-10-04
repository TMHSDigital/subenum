// Copyright (c) 2026 TM Hospitality Strategies
//
// Tool for generating custom wordlists for subdomain enumeration.
// For authorized use only.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
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

func main() {
	outputFile := flag.String("o", "wordlist.txt", "Path to output wordlist file")
	combineWith := flag.String("combine", "", "Combine each word with these prefixes (comma-separated)")
	addCommon := flag.Bool("common", true, "Add common subdomain prefixes")
	domainInfo := flag.String("domain", "", "Domain to extract potential subdomains from (e.g., company-name.com -> company, name)")
	verbose := flag.Bool("v", false, "Print every generated entry")
	flag.Parse()

	if *outputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: output file cannot be empty")
		os.Exit(1)
	}

	words := generate(options{common: *addCommon, domain: *domainInfo, combine: *combineWith})

	file, err := os.Create(*outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	writeErr := writeWordlist(file, words)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", *outputFile, firstErr(writeErr, closeErr))
		os.Exit(1)
	}

	if *verbose {
		for _, w := range words {
			fmt.Println(w)
		}
	}
	fmt.Fprintf(os.Stderr, "Wordlist generated at %s with %d unique entries\n", *outputFile, len(words))
	fmt.Fprintln(os.Stderr, "NOTE: Only use this tool to generate wordlists for domains you have explicit permission to test.")
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
