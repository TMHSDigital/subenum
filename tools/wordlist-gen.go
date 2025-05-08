// Copyright (c) 2025 TM Hospitality Strategies
//
// Tool for generating custom wordlists for subdomain enumeration
// Educational purposes only

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	// Command-line flags
	outputFile := flag.String("o", "wordlist.txt", "Path to output wordlist file")
	combineWith := flag.String("combine", "", "Combine each word with these prefixes (comma-separated)")
	addCommon := flag.Bool("common", true, "Add common subdomain prefixes")
	domainInfo := flag.String("domain", "", "Domain to extract potential subdomains from (e.g., company-name.com -> company, name)")
	flag.Parse()

	// Validate output file
	if *outputFile == "" {
		fmt.Println("Error: Output file cannot be empty")
		os.Exit(1)
	}

	// Create output file
	file, err := os.Create(*outputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Track added words to avoid duplicates
	addedWords := make(map[string]bool)

	// Add common subdomain prefixes if requested
	if *addCommon {
		fmt.Println("Adding common subdomain prefixes...")
		commonPrefixes := []string{
			"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
			"smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
			"portal", "admin", "host", "api", "dev", "web", "cloud", "email",
			"apps", "support", "app", "staging", "proxy", "beta", "gateway",
			"cdn", "auth", "intranet", "mobile", "sso", "help", "docs",
		}

		for _, prefix := range commonPrefixes {
			if !addedWords[prefix] {
				fmt.Fprintln(writer, prefix)
				addedWords[prefix] = true
				fmt.Printf("Added: %s\n", prefix)
			}
		}
	}

	// Process domain-specific terms if provided
	if *domainInfo != "" {
		fmt.Printf("Extracting terms from domain: %s\n", *domainInfo)

		// Remove TLD and split by separators
		domain := *domainInfo

		// Remove common TLDs
		domain = strings.TrimSuffix(domain, ".com")
		domain = strings.TrimSuffix(domain, ".org")
		domain = strings.TrimSuffix(domain, ".net")
		domain = strings.TrimSuffix(domain, ".edu")
		domain = strings.TrimSuffix(domain, ".gov")
		domain = strings.TrimSuffix(domain, ".io")

		// Split by common separators
		parts := strings.FieldsFunc(domain, func(r rune) bool {
			return r == '.' || r == '-' || r == '_'
		})

		for _, part := range parts {
			if len(part) > 2 && !addedWords[part] { // Only add if length > 2
				fmt.Fprintln(writer, part)
				addedWords[part] = true
				fmt.Printf("Added: %s\n", part)
			}
		}
	}

	// Process combination prefixes if provided
	if *combineWith != "" {
		prefixes := strings.Split(*combineWith, ",")
		fmt.Printf("Combining with prefixes: %v\n", prefixes)

		// Create a temporary copy of addedWords to iterate over
		wordsCopy := make([]string, 0, len(addedWords))
		for word := range addedWords {
			wordsCopy = append(wordsCopy, word)
		}

		// Create combinations
		for _, prefix := range prefixes {
			prefix = strings.TrimSpace(prefix)
			if prefix == "" {
				continue
			}

			// Add the prefix itself
			if !addedWords[prefix] {
				fmt.Fprintln(writer, prefix)
				addedWords[prefix] = true
				fmt.Printf("Added: %s\n", prefix)
			}

			// Create combinations with existing words
			for _, word := range wordsCopy {
				combination := prefix + "-" + word
				if !addedWords[combination] {
					fmt.Fprintln(writer, combination)
					addedWords[combination] = true
					fmt.Printf("Added: %s\n", combination)
				}
			}
		}
	}

	// Count total words
	fmt.Printf("\nWordlist generated at %s with %d unique entries\n", *outputFile, len(addedWords))
	fmt.Println("\nNOTE: Only use this tool to generate wordlists for domains you have explicit permission to test.")
}
