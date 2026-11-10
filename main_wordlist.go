package main

import (
	"strings"

	"github.com/TMHSDigital/subenum/data"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// bundledWordlistName is how notices refer to the embedded list (#63).
const bundledWordlistName = "bundled top-5000 list (SecLists)"

// wordlistPaths is the repeatable -w flag (#199). Each -w adds a file; the
// files are read in order and their lines concatenated, so Prepare dedupes
// across them.
//
// A config-file or SUBENUM_W value is a default: it is replaced, not added
// to, by a later source or by the first -w on the command line.
type wordlistPaths struct {
	paths   []string
	replace bool // the current paths are a default; the next Set replaces them
}

func (w *wordlistPaths) String() string {
	if w == nil {
		return ""
	}
	return strings.Join(w.paths, ",")
}

// Set adds a path. An empty value adds nothing, so -w "" still means the
// bundled list.
func (w *wordlistPaths) Set(v string) error {
	if w.replace {
		w.paths, w.replace = nil, false
	}
	if v != "" {
		w.paths = append(w.paths, v)
	}
	return nil
}

// markDefault records that the current paths came from the config file or
// the environment rather than the command line.
func (w *wordlistPaths) markDefault() { w.replace = true }

// readsStdin reports whether any -w entry is "-".
func (w *wordlistPaths) readsStdin() bool { return countStdin(w.paths) > 0 }

// describe names the wordlists for notices: the paths, comma-separated.
func (w *wordlistPaths) describe() string { return strings.Join(w.paths, ", ") }

// readWordlist returns the wordlist lines from every -w file in order, or the
// bundled list when -w is not set.
func readWordlist(f cliFlags, in *runtimeInputs) ([]string, error) {
	if len(f.wordlists.paths) == 0 {
		return wordlist.ReadLinesFrom(strings.NewReader(data.Subdomains5k))
	}
	var lines []string
	for _, p := range f.wordlists.paths {
		l, err := in.readLines(p)
		if err != nil {
			return nil, err
		}
		lines = append(lines, l...)
	}
	return lines, nil
}

// countStdin counts the "-" entries in paths.
func countStdin(paths []string) int {
	n := 0
	for _, p := range paths {
		if p == wordlist.Stdin {
			n++
		}
	}
	return n
}
