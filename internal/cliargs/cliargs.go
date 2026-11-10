// Package cliargs parses command lines whose flags may follow positional
// arguments. It is shared by subenum and the wordlist-gen tool.
package cliargs

import (
	"flag"
	"strings"
)

// Parse parses flags that appear anywhere in args and returns the positional
// arguments in order. The standard flag package stops at the first non-flag
// argument, which silently dropped every flag written after the domain (#29).
// Arguments after a "--" terminator are all treated as positionals; a "--"
// that is the value of a flag, as in "-o --", is not a terminator.
func Parse(fs *flag.FlagSet, args []string) ([]string, error) {
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
