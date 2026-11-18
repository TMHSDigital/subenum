package cli

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// These fixtures are corrupt files, not incomplete sets of valid results:
// parsing must fail without returning the names read before the bad line.
var malformedBaselines = []struct{ name, content string }{
	{"truncated JSON array", `[{"subdomain":`},
	{"unterminated CSV quote", "subdomain,type,value\n\"www.example.com,A,192.0.2.1\n"},
	// encoding/csv enforces the header's field count. Keep that rejection
	// explicit instead of treating a short row as a names-only result.
	{"short CSV row", "subdomain,type,value\nwww.example.com\n"},
	{"bad middle JSONL line", "{\"subdomain\":\"first.example.com\"}\n{\"subdomain\":}\n{\"subdomain\":\"last.example.com\"}\n"},
}

func TestParseBaselineMalformedInput(t *testing.T) {
	for _, tc := range malformedBaselines {
		t.Run(tc.name, func(t *testing.T) {
			b, err := parseBaseline([]byte(tc.content))
			if err == nil {
				t.Fatal("malformed baseline was accepted")
			}
			if len(b.names) != 0 || len(b.records) != 0 || b.hasRecords {
				t.Fatalf("malformed baseline returned partial results: %+v", b)
			}
		})
	}
}

func TestParseBaselineTextChangesAndBOM(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		want          []string
		hasRecords    bool
	}{
		// A text baseline is a list of names, not an instruction to replay
		// changes: even the removed-name line remains part of that list.
		{"diff text", "+ new.example.com\n- old.example.com\n~ cdn.example.com A=192.0.2.1 (was A=192.0.2.2)\n", []string{"cdn.example.com", "new.example.com", "old.example.com"}, false},
		{"BOM JSON array", "\uFEFF" + `[{"subdomain":"WWW.example.com."}]`, []string{"www.example.com"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := parseBaseline([]byte(tc.content))
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Sorted(maps.Keys(b.names)); !slices.Equal(got, tc.want) {
				t.Errorf("names %v, want %v", got, tc.want)
			}
			if b.hasRecords != tc.hasRecords || len(b.records) != 0 {
				t.Errorf("hasRecords %v, records %v; want %v and no records", b.hasRecords, b.records, tc.hasRecords)
			}
		})
	}
}

// A baseline may come from outside the run (a downloaded artifact): names no
// DNS host has, with escape sequences or markup, are dropped instead of being
// reported as removed into the terminal or the Action's step summary.
func TestParseBaselineDropsImplausibleNames(t *testing.T) {
	content := `{"subdomain":"\u001b[2J\u001b[31mPWNED gone.lab.example"}` + "\n" +
		`{"subdomain":"a` + "`" + `](https://x.invalid).lab.example"}` + "\n" +
		`{"subdomain":"tab\there.lab.example"}` + "\n" +
		`{"subdomain":"www.lab.example"}` + "\n" +
		`{"subdomain":"_dmarc.lab.example"}` + "\n" +
		`{"subdomain":"*.lab.example"}` + "\n"
	b, err := parseBaseline([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"*.lab.example", "_dmarc.lab.example", "www.lab.example"}
	if got := slices.Sorted(maps.Keys(b.names)); !slices.Equal(got, want) {
		t.Errorf("names %q, want %q", got, want)
	}
}

func TestE2EDiffRejectsMalformedBaselines(t *testing.T) {
	valid := writeFile(t, "valid.txt", "www.example.com\n")
	for _, tc := range malformedBaselines {
		t.Run(tc.name, func(t *testing.T) {
			bad := writeFile(t, "bad.txt", tc.content)
			for _, files := range [][]string{{bad, valid}, {valid, bad}} {
				code, stdout, stderr := runCLIStreams(t, append([]string{"diff"}, files...)...)
				if code != exitFailure || stdout != "" || !strings.Contains(stderr, "Error: reading "+bad+":") {
					t.Errorf("diff %v: exit %d, stdout %q, stderr %q; want failure naming the bad file and no output", files, code, stdout, stderr)
				}
			}
		})
	}
}
