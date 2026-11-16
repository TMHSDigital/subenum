package cliargs

import (
	"errors"
	"flag"
	"io"
	"reflect"
	"testing"
)

type parsed struct {
	out     string
	threads int
	verbose bool
}

func newFlagSet() (*flag.FlagSet, *parsed) {
	p := &parsed{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&p.out, "o", "", "output")
	fs.IntVar(&p.threads, "t", 1, "threads")
	fs.BoolVar(&p.verbose, "v", false, "verbose")
	return fs, p
}

func TestParse(t *testing.T) {
	cases := []struct {
		name string
		args []string
		pos  []string
		want parsed
	}{
		{"no args", nil, nil, parsed{threads: 1}},
		{"flags before positional", []string{"-t", "5", "a.com"}, []string{"a.com"}, parsed{threads: 5}},
		{"flags after positional", []string{"a.com", "-t", "5", "-v"}, []string{"a.com"}, parsed{threads: 5, verbose: true}},
		{"flags on both sides", []string{"-v", "a.com", "-o", "x"}, []string{"a.com"}, parsed{out: "x", threads: 1, verbose: true}},
		{"positionals keep order", []string{"a.com", "-t", "3", "b.com", "c.com"}, []string{"a.com", "b.com", "c.com"}, parsed{threads: 3}},
		{"leading terminator", []string{"--", "-t", "5"}, []string{"-t", "5"}, parsed{threads: 1}},
		{"terminator stops flag parsing", []string{"-o", "x", "--", "a.com", "-t"}, []string{"a.com", "-t"}, parsed{out: "x", threads: 1}},
		{"terminator after a positional", []string{"a.com", "--", "-v"}, []string{"a.com", "-v"}, parsed{threads: 1}},
		{"-- as a flag value is not a terminator", []string{"-o", "--", "a.com", "-t", "5"}, []string{"a.com"}, parsed{out: "--", threads: 5}},
		{"-- after -flag=value is a terminator", []string{"-o=x", "--", "-t"}, []string{"-t"}, parsed{out: "x", threads: 1}},
		{"terminator after a bool flag", []string{"-v", "--", "-weird.example"}, []string{"-weird.example"}, parsed{threads: 1, verbose: true}},
		{"double-dash flag value", []string{"--o", "--", "a.com"}, []string{"a.com"}, parsed{out: "--", threads: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, p := newFlagSet()
			pos, err := Parse(fs, tc.args)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(pos, tc.pos) {
				t.Errorf("positionals = %q, want %q", pos, tc.pos)
			}
			if *p != tc.want {
				t.Errorf("flags = %+v, want %+v", *p, tc.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	fs, _ := newFlagSet()
	if _, err := Parse(fs, []string{"a.com", "-bogus"}); err == nil {
		t.Error("unknown flag after positional: expected error")
	}
	fs, _ = newFlagSet()
	if _, err := Parse(fs, []string{"a.com", "-t", "x"}); err == nil {
		t.Error("bad value after positional: expected error")
	}
	fs, _ = newFlagSet()
	if _, err := Parse(fs, []string{"a.com", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h after positional: err = %v, want flag.ErrHelp", err)
	}
}
