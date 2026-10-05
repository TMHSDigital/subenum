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
		if code := run([]string{"-combine", "dev," + bad, "-o", filepath.Join(dir, "c.txt")}, io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "invalid -combine prefix") {
			t.Errorf("-combine %q: exit %d, stderr %q", bad, code, stderr.String())
		}
	}
}
