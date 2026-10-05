package main

import (
	_ "embed"
	"strings"

	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// bundledWordlist is the default wordlist used when -w is omitted: the 5,000
// most common subdomain labels from SecLists (MIT; the notice is kept in the
// file's header), so a first scan finds something real (#63).
//
//go:embed data/subdomains-5k.txt
var bundledWordlist string

// bundledWordlistName is how notices refer to the embedded list.
const bundledWordlistName = "bundled top-5000 list (SecLists)"

// readWordlist returns the wordlist lines from -w, or the bundled list when
// -w is not set.
func readWordlist(f cliFlags) ([]string, error) {
	if f.wordlistFile == "" {
		return wordlist.ReadLinesFrom(strings.NewReader(bundledWordlist))
	}
	return wordlist.ReadLines(f.wordlistFile)
}
