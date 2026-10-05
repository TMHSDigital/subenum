package subenum_test

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/TMHSDigital/subenum/pkg/subenum"
)

// Scan runs an enumeration to completion and hands back everything it found.
// Simulate invents the results, so this example sends no DNS queries; drop it
// and give a Resolver to scan a domain you are allowed to test.
func Example() {
	results, stats, err := subenum.Scan(context.Background(), subenum.Config{
		Domain:   "example.com",
		Words:    []string{"www", "mail", "api"},
		Simulate: true,
		HitRate:  100,
		Seed:     1,
	})
	if err != nil {
		log.Fatal(err)
	}

	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Println(n)
	}
	fmt.Printf("resolved %d of %d candidates\n", stats.Found, stats.Total())

	// Output:
	// api.example.com
	// mail.example.com
	// www.example.com
	// resolved 3 of 3 candidates
}

// Run streams events while the scan is still going, which is what a long scan
// or a progress display wants. The channel always ends with one KindDone
// event carrying the final counts.
func ExampleRun() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	events, err := subenum.Run(ctx, subenum.Config{
		Domain:   "example.com",
		Words:    []string{"www", "dev", "stage", "api"},
		Simulate: true,
		HitRate:  100,
		Seed:     1,
	})
	if err != nil {
		fmt.Println("cannot start:", err)
		return
	}

	var names []string
	var stats subenum.Stats
	for ev := range events {
		switch ev.Kind {
		case subenum.KindResult:
			names = append(names, ev.Result.Name)
		case subenum.KindNotice:
			fmt.Printf("notice (%s): %s\n", ev.Notice, ev.Message)
		case subenum.KindError:
			fmt.Println("error:", ev.Message)
		case subenum.KindDone:
			stats = ev.Stats
		}
	}

	sort.Strings(names)
	fmt.Println("found:", len(names))
	for _, n := range names {
		fmt.Println(" ", n)
	}
	fmt.Println("did not exist:", stats.NXDomain)

	// Output:
	// found: 4
	//   api.example.com
	//   dev.example.com
	//   stage.example.com
	//   www.example.com
	// did not exist: 0
}

// A zero Config is a complete one: every field falls back to the same default
// the command line uses.
func ExampleConfig() {
	cfg := subenum.Config{Domain: "example.com"}

	fmt.Println("resolver:", subenum.DefaultResolver)
	fmt.Println("workers:", subenum.DefaultConcurrency)
	fmt.Println("timeout:", subenum.DefaultTimeout)
	fmt.Println("attempts:", subenum.DefaultAttempts)
	fmt.Println("words:", len(subenum.DefaultWords()))
	fmt.Println("domain:", cfg.Domain)

	// Output:
	// resolver: 8.8.8.8:53
	// workers: 100
	// timeout: 1s
	// attempts: 1
	// words: 5000
	// domain: example.com
}

// Recursion enumerates the wordlist again under each name it finds. Every
// level multiplies the candidate count by the size of the wordlist, so cap it
// with MaxQueries and pace it with Rate.
func ExampleConfig_recursive() {
	results, stats, err := subenum.Scan(context.Background(), subenum.Config{
		Domain:     "example.com",
		Words:      []string{"dev", "api"},
		Recursive:  true,
		Depth:      2,
		MaxQueries: 100,
		Rate:       50,
		Exclude:    []string{"*.dev.example.com"},
		Simulate:   true,
		HitRate:    100,
		Seed:       1,
	})
	if err != nil {
		log.Fatal(err)
	}

	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Println(n)
	}
	fmt.Println("out of scope, never queried:", stats.Excluded)

	// Output:
	// api.api.example.com
	// api.example.com
	// dev.api.example.com
	// dev.example.com
	// out of scope, never queried: 2
}
