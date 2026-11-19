package scan

import (
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// TestRecursionCeilingOf covers #403: with a separate list for depth 2 and
// below, each level multiplies by that list's length, not the wordlist's.
func TestRecursionCeilingOf(t *testing.T) {
	if got := RecursionCeilingOf(10, 2, 3); got != 10+20+40 {
		t.Errorf("ceiling(10, 2, 3) = %g, want 70", got)
	}
	if got, want := RecursionCeilingOf(7, 7, 3), RecursionCeiling(7, 3); got != want {
		t.Errorf("ceiling(7, 7, 3) = %g, want RecursionCeiling's %g", got, want)
	}
	if got := RecursionCeilingOf(5, 0, 3); got != 5 {
		t.Errorf("ceiling(5, 0, 3) = %g, want 5: nothing below depth 1", got)
	}
}

// TestRecursiveEntriesBelowDepthOne covers #403: the root tries Entries, and
// every expansion below it tries RecursiveEntries.
func TestRecursiveEntriesBelowDepthOne(t *testing.T) {
	cfg := Config{Entries: []string{"www", "api"}, RecursiveEntries: []string{"x", "y"}, Recursive: true}
	d := testDispatcher(cfg, 3)
	if got := drain(d); !slices.Equal(got, []string{"www.example.com", "api.example.com"}) {
		t.Fatalf("depth 1: %v", got)
	}
	d.expand(job{domain: "www.example.com", depth: 1})
	if d.remaining != 2 {
		t.Errorf("remaining %d after one expansion, want 2", d.remaining)
	}
	if got := drain(d); !slices.Equal(got, []string{"x.www.example.com", "y.www.example.com"}) {
		t.Fatalf("depth 2: %v", got)
	}
	d.expand(job{domain: "x.www.example.com", depth: 2})
	if got := drain(d); !slices.Equal(got, []string{"x.x.www.example.com", "y.x.www.example.com"}) {
		t.Fatalf("depth 3: %v", got)
	}

	// Without -recursive the list is never used.
	flat := testDispatcher(Config{Entries: []string{"www"}, RecursiveEntries: []string{"x"}}, 1)
	if flat.cfg.RecursiveEntries != nil {
		t.Error("a flat scan kept RecursiveEntries")
	}
}

// TestCapCountsRecursiveEntriesRemainder covers #403 with #301 and #361: a
// budget reached while expansions below depth 1 are queued counts their
// remainder by RecursiveEntries, so admitted, skipped and excluded still add
// up to what the scan with no budget generates.
func TestCapCountsRecursiveEntriesRemainder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
		deep    []string
		exclude []string
	}{
		{"single labels", []string{"a", "b", "c"}, []string{"x", "y", "z", "w"}, []string{"y.a.example.com", "*.b.example.com"}},
		{"single labels no exclusions", []string{"a", "b", "c"}, []string{"x", "y", "z", "w"}, nil},
		{"multi-label", []string{"b", "a.b", "c"}, []string{"a", "x", "q.r"}, nil},
		{"multi-label with exclusions", []string{"b", "a.b", "c"}, []string{"a", "x", "q.r"}, []string{"x.b.example.com"}},
	} {
		cfg := Config{Entries: tc.entries, RecursiveEntries: tc.deep, Recursive: true, MaxQueries: 3, Exclude: tc.exclude}
		find := func(d *dispatcher) {
			for _, e := range tc.entries[:2] {
				d.expand(job{domain: e + ".example.com", depth: 1})
			}
		}
		full := cfg
		full.MaxQueries = 0
		all := testDispatcher(full, 2)
		find(all)
		candidates := len(drain(all)) + all.excluded

		d := testDispatcher(cfg, 2)
		if _, ok := d.next(); !ok {
			t.Fatal("no job")
		}
		find(d)
		admitted := 1 + len(drain(d))
		if !d.capped {
			t.Fatalf("%s: not capped after %d jobs", tc.name, admitted)
		}
		if d.excluded != all.excluded || admitted+d.skipped+d.excluded != candidates {
			t.Errorf("%s: admitted %d skipped %d excluded %d, want %d excluded and %d in all",
				tc.name, admitted, d.skipped, d.excluded, all.excluded, candidates)
		}
	}
}

// TestResumeDepthsUseRecursiveEntries covers #403: a resumed parent is
// placed at depth 2 when its first label is a RecursiveEntries entry under a
// depth-1 parent, even if that label is not in Entries.
func TestResumeDepthsUseRecursiveEntries(t *testing.T) {
	cfg := Config{
		Domain: "example.com", Entries: []string{"www"}, RecursiveEntries: []string{"x"}, Recursive: true,
		ResumeParents: []string{"www.example.com", "x.www.example.com", "www.x.example.com"},
	}
	got := resumeDepths(cfg)
	want := map[string]int{"www.example.com": 1, "x.www.example.com": 2}
	if !maps.Equal(got, want) {
		t.Errorf("depths %v, want %v", got, want)
	}
}

// TestRunRecursiveEntries covers #403 end to end: the root tries the three
// entries, and each level below tries only the recursive entry.
func TestRunRecursiveEntries(t *testing.T) {
	zone := map[string]bool{
		"www.example.com": true, "api.example.com": true,
		"x.www.example.com": true, "x.x.www.example.com": true,
		"www.www.example.com": true, // only an Entries label reaches it
	}
	var mu sync.Mutex
	var asked []string
	addr, stop := startUDPDNS(t, func(name string, _ uint16) ([4]byte, bool) {
		mu.Lock()
		asked = append(asked, name)
		mu.Unlock()
		return [4]byte{192, 0, 2, 5}, zone[name]
	})
	defer stop()
	cfg := Config{
		Domain: "example.com", Entries: []string{"www", "api", "dev"}, RecursiveEntries: []string{"x"},
		Concurrency: 4, Timeout: time.Second, Attempts: 1, Types: []string{"A"},
		Recursive: true, Depth: 3,
		Resolver: dns.NewResolver(time.Second, addr), DNSServer: addr,
	}
	found, _ := runCollect(t, cfg, 0)
	want := map[string]bool{"www.example.com": true, "api.example.com": true, "x.www.example.com": true, "x.x.www.example.com": true}
	if !maps.Equal(found, want) {
		t.Errorf("found %v, want %v", found, want)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, name := range asked {
		if name == "www.www.example.com" || name == "api.www.example.com" {
			t.Errorf("an Entries label was tried below depth 1: %s", name)
		}
	}
}
