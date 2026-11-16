package candidates

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestSet covers #248's shared set: names from several sources are added
// once, after the wordlist, and the caller's -seeds map is never written to.
func TestSet(t *testing.T) {
	shared := map[string]struct{}{"seed.example.com": {}}
	c := New("example.com", []string{"www", "mail"}, shared)
	if n := c.Add("ct", nil); n != 0 || len(c.Seeds()) != 1 {
		t.Fatalf("no names: added %d, seeds %v", n, c.Seeds())
	}
	if got := c.SourcesOf("www.example.com"); !slices.Equal(got, []string{"wordlist"}) {
		t.Errorf("no source names: sources = %v, want wordlist", got)
	}
	if n := c.Add("wayback", []string{"api", "www", "bad name!"}); n != 1 {
		t.Errorf("first source added %d, want 1 (api)", n)
	}
	if n := c.Add("axfr", []string{"api", "old", "OLD"}); n != 1 {
		t.Errorf("second source added %d, want 1 (old)", n)
	}
	// #273: every source that proposed a name, the wordlist first; a name no
	// source gave (an entry, or a -recursive child) is the wordlist's.
	for name, want := range map[string][]string{
		"www.example.com":      {"wordlist", "wayback"},
		"WWW.Example.com":      {"wordlist", "wayback"},
		"mail.example.com":     {"wordlist"},
		"api.example.com":      {"wayback", "axfr"},
		"old.example.com":      {"axfr"},
		"mail.api.example.com": {"wordlist"},
	} {
		if got := c.SourcesOf(name); !slices.Equal(got, want) {
			t.Errorf("sources of %s = %v, want %v", name, got, want)
		}
	}
	if want := []string{"www", "mail", "api", "old"}; !slices.Equal(c.Entries(), want) {
		t.Errorf("entries = %v, want %v", c.Entries(), want)
	}
	if _, ok := c.Seeds()["old.example.com"]; !ok || len(shared) != 1 {
		t.Errorf("seeds = %v (shared %v): want the names added to a copy only", c.Seeds(), shared)
	}
	if got := (*Set)(nil).SourcesOf("www.example.com"); !slices.Equal(got, FromWordlist) {
		t.Errorf("nil set: sources = %v, want wordlist", got)
	}
}

// TestNoWordlistSizedMap covers #321: merging a few source names or
// permutations into a large wordlist checks them against the entries without
// building a map as large as the wordlist.
func TestNoWordlistSizedMap(t *testing.T) {
	const size = 200_000 // a map of these would take several MB
	entries := make([]string, size, size+64)
	for i := range entries {
		entries[i] = fmt.Sprintf("w%d", i)
	}
	allocated := func(fn func()) uint64 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	const limit = 1 << 20

	c := New("example.com", entries, nil)
	var added int
	if b := allocated(func() { added = c.Add("ct", []string{"api", "w7", "dev"}) }); b > limit {
		t.Errorf("Add allocated %d bytes, want at most %d", b, limit)
	}
	if added != 2 || len(c.Entries()) != size+2 {
		t.Errorf("added %d (%d entries), want 2 (%d)", added, len(c.Entries()), size+2)
	}
	if got := c.SourcesOf("w7.example.com"); !slices.Equal(got, []string{"wordlist", "ct"}) {
		t.Errorf("sources of w7 = %v, want [wordlist ct]", got)
	}

	var perms []string
	if b := allocated(func() { perms, _ = Permutations("example.com", entries, []string{"api"}) }); b > limit {
		t.Errorf("Permutations allocated %d bytes, want at most %d", b, limit)
	}
	if len(perms) == 0 || slices.Contains(perms, "api") {
		t.Errorf("permutations = %v", perms)
	}
}

// TestPermutationsRespectNameLength covers #111: candidates whose full name
// passes 253 characters are dropped, not queried.
func TestPermutationsRespectNameLength(t *testing.T) {
	label := strings.Repeat("a", 60)
	target := strings.Join([]string{label, label, label, "example"}, ".") // 191 characters
	seed := strings.Repeat("b", 55) + "." + target                        // 247 characters
	perms, tooLong := Permutations(target, nil, RelativeSeeds(target, []string{seed}, nil))
	if tooLong == 0 || len(perms) == 0 {
		t.Fatalf("%d candidates, %d too long; want some of each", len(perms), tooLong)
	}
	for _, c := range perms {
		if n := len(c) + 1 + len(target); n > 253 {
			t.Errorf("candidate %s is %d characters long", c, n)
		}
	}
}
