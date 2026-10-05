package main

import (
	"strings"

	"github.com/TMHSDigital/subenum/data"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// bundledWordlistName is how notices refer to the embedded list (#63).
const bundledWordlistName = "bundled top-5000 list (SecLists)"

// readWordlist returns the wordlist lines from -w, or the bundled list when
// -w is not set.
func readWordlist(f cliFlags) ([]string, error) {
	if f.wordlistFile == "" {
		return wordlist.ReadLinesFrom(strings.NewReader(data.Subdomains5k))
	}
	return wordlist.ReadLines(f.wordlistFile)
}
