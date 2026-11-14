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

// prepareWordlist normalizes the lines of every -w file in order, or the
// bundled list when -w is not set, as it reads them: the raw lines of a
// multi-million-line list are never all held at once (#248).
func prepareWordlist(f cliFlags, in *runtimeInputs) (*wordlist.Prepared, error) {
	pr := wordlist.NewPreparer()
	if len(f.wordlists.paths) == 0 {
		if err := wordlist.EachLine(strings.NewReader(data.Subdomains5k), pr.Add); err != nil {
			return nil, err
		}
		return pr.Prepared(), nil
	}
	for _, p := range f.wordlists.paths {
		var err error
		if p == wordlist.Stdin && in.stdin != nil {
			err = wordlist.EachLine(in.stdin, pr.Add)
		} else {
			err = wordlist.EachLineOf(p, pr.Add)
		}
		if err != nil {
			return nil, err
		}
	}
	return pr.Prepared(), nil
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
