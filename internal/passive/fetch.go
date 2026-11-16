package passive

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// UserAgent is the User-Agent the sources send for product, such as
// "subenum/v1.2.3" or "subenum-library" (#355).
func UserAgent(product string) string {
	return product + " (+https://github.com/TMHSDigital/subenum)"
}

// Lookup is one source's answer for a domain (#130, #193). The CLI, the TUI
// and pkg/subenum all sort answers this way (#355).
type Lookup struct {
	Source  string   // -sources name: ct, wayback
	Names   []string // relative to the domain
	Fetched bool     // the lookup succeeded (Names may still be empty)
	Err     string
	// Truncated says why a source that succeeded stopped at one of its
	// limits, so some hosts may be missing (#272).
	Truncated string
}

// Gather calls ask(i) for every i below n at once (#271) and sorts each
// answer: names that come with a *Truncated are kept and the reason noted
// (#272); any other error drops them. The results keep the order of i.
func Gather(n int, ask func(i int) ([]string, error)) []Lookup {
	res := make([]Lookup, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			names, err := ask(i)
			var tr *Truncated
			switch {
			case errors.As(err, &tr):
				res[i].Truncated = err.Error()
			case err != nil:
				res[i].Err = err.Error()
				return
			}
			res[i].Names, res[i].Fetched = names, true
		})
	}
	wg.Wait()
	return res
}

// FetchAll asks the built-in sources called names for domain's names at
// once, in the order of names.
func FetchAll(ctx context.Context, names []string, opts Options, domain string) []Lookup {
	res := Gather(len(names), func(i int) ([]string, error) {
		src, err := New(names[i], opts)
		if err != nil { // callers admit only known names
			return nil, err
		}
		return src.Names(ctx, domain)
	})
	for i := range res {
		res[i].Source = names[i]
	}
	return res
}

// AddedLine reports what a source proposed for target and how many of its
// names were not candidates already; the CLI and the TUI print the same line.
func AddedLine(label string, names int, target string, added int) string {
	return fmt.Sprintf("%s: %d names under %s, %d of them new candidates", label, names, target, added)
}
