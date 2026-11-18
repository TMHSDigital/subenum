package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestGenerateDeterministic covers #45: -combine used to iterate a map, so the
// order changed on every run.
func TestGenerateDeterministic(t *testing.T) {
	o := options{common: true, domain: "acme-corp.com", combine: "qa,uat"}
	first := generate(o)
	for i := 0; i < 20; i++ {
		if got := generate(o); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d produced a different order", i)
		}
	}
	// Combinations follow the order of the base words.
	idx := map[string]int{}
	for i, w := range first {
		idx[w] = i
	}
	order := []string{"www", "acme", "qa", "qa-www", "qa-mail", "qa-acme", "uat", "uat-www"}
	for i := 1; i < len(order); i++ {
		if idx[order[i-1]] >= idx[order[i]] {
			t.Errorf("%q should come before %q", order[i-1], order[i])
		}
	}
}

func TestGenerateDedupAndCase(t *testing.T) {
	got := generate(options{domain: "Shop.Example.com", combine: "WWW, shop ,"})
	want := []string{"shop", "example", "www", "www-shop", "www-example", "shop-example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("generate = %q, want %q", got, want)
	}
}

func TestDomainTerms(t *testing.T) {
	tests := map[string][]string{
		"acme-corp.com":       {"acme", "corp"},
		"acme.co.uk":          {"acme"},
		"shop.acme.com.au":    {"shop", "acme"},
		"big_name.dev.io":     {"big", "name", "dev"},
		"acme.technology":     {"acme"},
		"x.io":                nil,
		"single":              {"single"},
		"api-gateway.example": {"api", "gateway"},
	}
	for in, want := range tests {
		if got := domainTerms(in); !reflect.DeepEqual(got, want) {
			t.Errorf("domainTerms(%q) = %q, want %q", in, got, want)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriteWordlistReportsErrors(t *testing.T) {
	if err := writeWordlist(failingWriter{}, []string{"a", "b"}); err == nil {
		t.Fatal("expected write error")
	}
	var sb strings.Builder
	if err := writeWordlist(&sb, []string{"a", "b"}); err != nil || sb.String() != "a\nb\n" {
		t.Fatalf("got %q, %v", sb.String(), err)
	}
}

// TestRunGuards covers #59: an existing file is not overwritten without -f,
// an empty result exits non-zero, and invalid -combine prefixes are rejected.
func TestRunGuards(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(out, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder

	if code := run([]string{"-o", out}, io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "already exists") {
		t.Errorf("existing file: exit %d, stderr %q; want 1 and an already-exists error", code, stderr.String())
	}
	if got, _ := os.ReadFile(out); string(got) != "keep\n" {
		t.Errorf("existing file overwritten without -f: %q", got)
	}
	if code := run([]string{"-f", "-o", out}, io.Discard, io.Discard); code != 0 {
		t.Errorf("-f: exit %d, want 0", code)
	}
	if got, _ := os.ReadFile(out); !strings.Contains(string(got), "www\n") {
		t.Errorf("-f did not rewrite the file: %q", got)
	}

	empty := filepath.Join(dir, "empty.txt")
	if code := run([]string{"-common=false", "-o", empty}, io.Discard, io.Discard); code != 1 {
		t.Errorf("empty result: exit %d, want 1", code)
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Errorf("empty result still created %s", empty)
	}

	for _, bad := range []string{"shop!", "a b", "x.y"} {
		stderr.Reset()
		if code := run([]string{"-combine", "dev," + bad, "-o", filepath.Join(dir, "c.txt")}, io.Discard, &stderr); code != 2 || !strings.Contains(stderr.String(), "invalid -combine prefix") {
			t.Errorf("-combine %q: exit %d, stderr %q; want 2", bad, code, stderr.String())
		}
	}
}

// TestRunRejectsPositionalAndAcceptsDomain tests issue #120: a leftover
// positional is a usage error that points at -domain, while -domain itself
// works and accepts flags written after it.
func TestRunRejectsPositionalAndAcceptsDomain(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "wl.txt")
	var stderr strings.Builder

	// Without -domain, a positional should cause an error mentioning -domain
	if code := run([]string{"acme.com"}, io.Discard, &stderr); code != 2 || !strings.Contains(stderr.String(), "-domain") {
		t.Errorf("positional without -domain: exit %d, stderr %q; want 2 with -domain mentioned", code, stderr.String())
	}

	// -domain takes acme.com as its value; -o (written after it) is still parsed.
	if code := run([]string{"-domain", "acme.com", "-o", out}, io.Discard, &stderr); code != 0 {
		t.Errorf("valid -domain with trailing flags: exit %d, stderr %q; want 0", code, stderr.String())
	}

	// Check that the file was written
	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}
	if !strings.Contains(string(content), "www\n") {
		t.Errorf("expected 'www' in output; got %q", string(content))
	}
}

// TestRunEmptyOutputFile tests issue #120: empty -o should exit 2.
func TestRunEmptyOutputFile(t *testing.T) {
	var stderr strings.Builder
	if code := run([]string{"-o", ""}, io.Discard, &stderr); code != 2 || !strings.Contains(stderr.String(), "output file cannot be empty") {
		t.Errorf("empty -o: exit %d, stderr %q; want 2 with error message", code, stderr.String())
	}
}

// TestRunInvalidCombinePrefix tests issue #120: invalid -combine should exit 2.
func TestRunInvalidCombinePrefix(t *testing.T) {
	dir := t.TempDir()
	var stderr strings.Builder
	if code := run([]string{"-combine", "bad!.x", "-o", filepath.Join(dir, "c.txt")}, io.Discard, &stderr); code != 2 || !strings.Contains(stderr.String(), "invalid -combine prefix") {
		t.Errorf("invalid -combine prefix: exit %d, stderr %q; want 2 with error message", code, stderr.String())
	}
}

// TestRunTerminator tests that -- terminator works correctly.
func TestRunTerminator(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "wl.txt")
	var stderr strings.Builder

	// With --, all subsequent args are positionals and cause an error
	if code := run([]string{"-domain", "acme.com", "--", "-o", out}, io.Discard, &stderr); code != 2 || !strings.Contains(stderr.String(), "unexpected argument") {
		t.Errorf("-- terminator: exit %d, stderr %q; want 2", code, stderr.String())
	}
}

// TestRunInterspersedFlags checks that wordlist-gen uses the shared
// cliargs parser (#136): flags after a stray positional are still parsed (so
// an unknown one is a usage error), and "--" as a flag value is not a terminator.
func TestRunInterspersedFlags(t *testing.T) {
	var stderr strings.Builder
	if code := run([]string{"acme.com", "-bogus"}, io.Discard, &stderr); code != 2 || !strings.Contains(stderr.String(), "-bogus") {
		t.Errorf("unknown flag after positional: exit %d, stderr %q; want 2 naming -bogus", code, stderr.String())
	}

	// "-o --" sets the output path to "--"; flag parsing continues past the
	// positional, so -bogus is reported rather than "unexpected argument".
	stderr.Reset()
	code := run([]string{"-o", "--", "acme.com", "-bogus"}, io.Discard, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "-bogus") || strings.Contains(stderr.String(), "unexpected argument") {
		t.Errorf("-o -- then positional: exit %d, stderr %q; want 2 naming -bogus", code, stderr.String())
	}
}

// TestLearnLabelsEveryFormat covers #423: -from reads results in every output
// format and ranks the labels under the apex by how often they occur.
func TestLearnLabelsEveryFormat(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"text": "k8s.example.com\nFound: api.k8s.example.com\nstg.example.com\n",
		"json": `[{"subdomain":"k8s.example.com","records":[]},{"subdomain":"api.k8s.example.com","records":[]},{"subdomain":"stg.example.com","records":[]}]`,
		"jsonl": `{"subdomain":"k8s.example.com"}` + "\n" + `{"subdomain":"api.k8s.example.com"}` + "\n" +
			`{"subdomain":"stg.example.com"}` + "\n" + `{"type":"summary","verdict":"complete"}` + "\n",
		"csv": "subdomain,type,value\nk8s.example.com,A,192.0.2.1\napi.k8s.example.com,A,192.0.2.2\nstg.example.com,A,192.0.2.3\n",
	}
	for format, content := range files {
		path := filepath.Join(dir, format)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := learnLabels([]string{path}, "", 1)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		// k8s twice; api and stg once each, alphabetically.
		if want := []string{"k8s", "api", "stg"}; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: learned %q, want %q", format, got, want)
		}
	}
}

func TestLearnLabelsApexAndMinCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "res.txt")
	content := "int.dev.acme.co.uk\nvpn-int.acme.co.uk\nint.shop.acme.example\nwww.acme.example\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// acme.co.uk drops "co"; -domain names a deeper apex for its own names.
	got, err := learnLabels([]string{path}, "shop.acme.example", 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"int", "dev", "vpn-int", "www"}; !reflect.DeepEqual(got, want) {
		t.Errorf("learned %q, want %q", got, want)
	}
	if got, _ := learnLabels([]string{path}, "", 2); !reflect.DeepEqual(got, []string{"int"}) {
		t.Errorf("-min-count 2 learned %q, want only int", got)
	}
}

// TestRunFromLeadsAndDedups: learned labels come first and a common prefix
// they repeat is not written twice.
func TestRunFromLeadsAndDedups(t *testing.T) {
	dir := t.TempDir()
	res := filepath.Join(dir, "res.jsonl")
	if err := os.WriteFile(res, []byte(`{"subdomain":"k8s.example.com"}`+"\n"+`{"subdomain":"www.example.com"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "wl.txt")
	if code := run([]string{"-from", res, "-o", out}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if lines[0] != "k8s" || lines[1] != "www" || strings.Count(string(data), "\nwww\n") != 1 {
		t.Errorf("wordlist starts %q; want k8s, www first and www once", lines[:3])
	}
	if code := run([]string{"-from", filepath.Join(dir, "missing"), "-o", filepath.Join(dir, "x.txt")}, io.Discard, io.Discard); code != 1 {
		t.Errorf("missing -from file: exit %d, want 1", code)
	}
}
