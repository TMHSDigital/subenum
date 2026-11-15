package scan

import (
	"slices"
	"testing"
	"time"
)

// These tests drive the dispatcher's methods directly, with no goroutines,
// workers or DNS (#159).

func testDispatcher(cfg Config, maxDepth int) *dispatcher {
	if cfg.Domain == "" {
		cfg.Domain = "example.com"
	}
	cfg.scope = newScope(cfg.Exclude)
	return newDispatcher(cfg, maxDepth)
}

// TestNextChunkSize covers #184: chunks are at most maxChunk jobs, and a
// short wordlist goes out one job at a time so every worker gets some.
func TestNextChunkSize(t *testing.T) {
	big := testDispatcher(Config{Entries: makeEntries(10000)}, 1)
	if got := len(big.nextChunk(50)); got != maxChunk {
		t.Errorf("10000 entries, 50 workers: chunk of %d, want %d", got, maxChunk)
	}
	small := testDispatcher(Config{Entries: makeEntries(20)}, 1)
	for i := 0; i < 20; i++ {
		if got := len(small.nextChunk(100)); got != 1 {
			t.Fatalf("20 entries, 100 workers: chunk %d has %d jobs, want 1", i, got)
		}
	}
	if got := small.nextChunk(100); got != nil {
		t.Errorf("exhausted dispatcher returned %v", got)
	}
	mid := testDispatcher(Config{Entries: makeEntries(30)}, 1)
	if got := len(mid.nextChunk(10)); got != 3 {
		t.Errorf("30 entries, 10 workers: chunk of %d, want 3", got)
	}
}

// drain takes every job next will give, without completing any.
func drain(d *dispatcher) []string {
	var names []string
	for {
		j, ok := d.next()
		if !ok {
			return names
		}
		names = append(names, j.domain)
	}
}

// TestCapLeavesExcludedOutOfSkipped covers #238: a budget that runs out with
// only excluded candidates left counts them as excluded, not skipped, so the
// scan is still complete; in-scope candidates past it are still skipped.
func TestCapLeavesExcludedOutOfSkipped(t *testing.T) {
	entries := makeEntries(100)
	var excl []string
	for _, e := range entries[90:] {
		excl = append(excl, e+".example.com")
	}
	cfg := Config{Domain: "example.com", Entries: entries, MaxQueries: 90, Exclude: excl}
	d := testDispatcher(cfg, 1)
	if got := len(drain(d)); got != 90 {
		t.Fatalf("admitted %d, want 90", got)
	}
	if d.skipped != 0 || d.excluded != 10 {
		t.Errorf("skipped %d excluded %d, want 0 and 10", d.skipped, d.excluded)
	}

	cfg.MaxQueries = 80 // now 10 in-scope names are past the cap too
	d = testDispatcher(cfg, 1)
	drain(d)
	if d.skipped != 10 || d.excluded != 10 {
		t.Errorf("cap 80: skipped %d excluded %d, want 10 and 10", d.skipped, d.excluded)
	}
}

// Only a recursive scan with a multi-label entry can reach one name through
// two parents, so only it keeps a set of generated candidates (#248, #301);
// a flat scan, and a recursive one over single labels, rely on their entries
// being unique already.
func TestDispatcherVisitedSetOnlyForMultiLabelEntries(t *testing.T) {
	if flat := testDispatcher(Config{Entries: []string{"www", "a.b"}}, 1); flat.visited != nil || flat.expanded != nil {
		t.Error("a non-recursive scan allocated a visited or expanded set")
	}
	single := testDispatcher(Config{Entries: []string{"a", "b"}, Recursive: true}, 3)
	drain(single)
	single.expand(job{domain: "a.example.com", depth: 1})
	if got := drain(single); len(got) != 2 {
		t.Fatalf("children %v, want 2", got)
	}
	if single.visited != nil {
		t.Error("a recursive scan over single-label entries kept a per-candidate set")
	}

	// "a.b" under the root and "a" under b.example.com are one name.
	d := testDispatcher(Config{Entries: []string{"a.b", "a", "b"}, Recursive: true}, 3)
	if d.visited == nil {
		t.Fatal("a recursive scan with a multi-label entry kept no per-candidate set")
	}
	drain(d)
	d.expand(job{domain: "b.example.com", depth: 1})
	got := drain(d)
	if want := []string{"a.b.b.example.com", "b.b.example.com"}; !slices.Equal(got, want) {
		t.Errorf("children %v, want %v", got, want)
	}
}

// Jobs settle as they complete, in any order, and the watermark is the first
// entry not yet done.
func TestDispatcherSettlesOutOfOrder(t *testing.T) {
	d := testDispatcher(Config{Entries: []string{"www", "mail", "api"}, Recursive: true}, 1)
	drain(d)
	for _, root := range []int{2, 0} {
		d.complete(completion{root: root, finished: true})
	}
	if d.watermark != 1 {
		t.Errorf("watermark %d, want 1 (entry 1 not yet done)", d.watermark)
	}
	d.complete(completion{root: 1, finished: true})
	if d.watermark != 3 {
		t.Errorf("watermark %d, want 3", d.watermark)
	}
}

// TestCapCountsRecursiveRemainderWithoutBuildingIt covers #301: a budget
// reached in a recursive scan splits what is left into skipped and excluded
// with the same counts as generating every candidate would give.
func TestCapCountsRecursiveRemainderWithoutBuildingIt(t *testing.T) {
	entries := makeEntries(10)
	cfg := Config{
		Domain: "example.com", Entries: entries, Recursive: true, MaxQueries: 12,
		Exclude: []string{
			entries[1] + ".example.com",                     // tested before the cap: excluded as generated
			entries[9] + ".example.com",                     // past the cap
			entries[0] + "." + entries[0] + ".example.com",  // generated before the cap
			entries[7] + "." + entries[0] + ".example.com",  // past the cap
			"absent." + entries[0] + ".example.com",         // not a candidate
			entries[3] + ".other.example.com",               // parent never expanded
			"*." + entries[2] + ".example.com",              // whole subtree of a found parent
			"*.deep." + entries[4] + ".example.com",         // excludes nothing queued
			entries[5] + "." + entries[4] + ".example.com.", // past the cap, written with a trailing dot
		},
	}
	// The same scan with no budget, generating every candidate, gives the
	// counts the capped one must reach without building them.
	find := func(d *dispatcher) {
		for _, i := range []int{0, 2, 4} {
			d.expand(job{domain: entries[i] + ".example.com", depth: 1})
		}
	}
	full := cfg
	full.MaxQueries = 0
	all := testDispatcher(full, 2)
	find(all)
	candidates := len(drain(all))

	d := testDispatcher(cfg, 2)
	// Take 4 root jobs, then queue the found parents behind the root.
	for i := 0; i < 4; i++ {
		if _, ok := d.next(); !ok {
			t.Fatal("no job")
		}
	}
	find(d)
	admitted := 4 + len(drain(d))
	if admitted != 12 || !d.capped {
		t.Fatalf("admitted %d capped %v, want 12 and true", admitted, d.capped)
	}
	if d.excluded != all.excluded || d.skipped != candidates-admitted {
		t.Errorf("capped: excluded %d skipped %d, want %d and %d", d.excluded, d.skipped, all.excluded, candidates-admitted)
	}
	if d.remaining != 0 || len(d.frontier) != 0 {
		t.Errorf("remaining %d frontier %d after the cap, want 0 and 0", d.remaining, len(d.frontier))
	}
}

// A resumed parent that the resumed scan finds again is expanded once, and
// counted once when a budget stops admission (#301).
func TestDispatcherExpandsAResumedParentOnce(t *testing.T) {
	cfg := Config{
		Entries: []string{"a", "b"}, Recursive: true,
		ResumeParents: []string{"dev.example.com", "DEV.example.com."},
	}
	d := testDispatcher(cfg, 3)
	d.expand(job{domain: "dev.example.com", depth: 1})
	want := []string{"a.example.com", "b.example.com", "a.dev.example.com", "b.dev.example.com"}
	if got := drain(d); !slices.Equal(got, want) {
		t.Errorf("jobs %v, want %v", got, want)
	}

	cfg.MaxQueries = 1
	d = testDispatcher(cfg, 3)
	drain(d)
	d.expand(job{domain: "dev.example.com", depth: 1})
	if d.skipped != 3 {
		t.Errorf("skipped %d, want 3 (one root entry and dev's two children, once)", d.skipped)
	}
}

func TestDispatcherUnfinishedJobHoldsTheResumePoint(t *testing.T) {
	d := testDispatcher(Config{Entries: []string{"a", "b"}}, 1)
	drain(d)
	d.pending = 2
	d.complete(completion{root: 0, finished: false}) // cut short by cancellation
	d.complete(completion{root: 1, finished: true})
	if d.watermark != 0 || d.pending != 0 {
		t.Errorf("watermark %d pending %d, want 0 and 0", d.watermark, d.pending)
	}
}

func TestDispatcherExcludes(t *testing.T) {
	d := testDispatcher(Config{Entries: []string{"www", "vpn", "mail"}, Exclude: []string{"vpn.example.com"}}, 1)
	if got := drain(d); !slices.Equal(got, []string{"www.example.com", "mail.example.com"}) {
		t.Fatalf("jobs %v", got)
	}
	if d.excluded != 1 || d.watermark != 0 {
		t.Errorf("excluded %d watermark %d, want 1 and 0", d.excluded, d.watermark)
	}
	// A parent whose whole subtree is excluded adds no children.
	d2 := testDispatcher(Config{Entries: []string{"a", "b"}, Exclude: []string{"*.dev.example.com"}}, 2)
	d2.expand(job{domain: "dev.example.com", depth: 1})
	if d2.excluded != 2 || d2.remaining != 2 {
		t.Errorf("excluded %d remaining %d, want 2 children excluded and the 2 roots left", d2.excluded, d2.remaining)
	}
}

func TestDispatcherMaxQueries(t *testing.T) {
	d := testDispatcher(Config{Entries: makeEntries(5), MaxQueries: 2}, 1)
	if got := drain(d); len(got) != 2 {
		t.Fatalf("%d jobs, want 2", len(got))
	}
	if !d.capped || d.expired || d.skipped != 3 || d.total() != 2 {
		t.Errorf("capped %v expired %v skipped %d total %d, want true false 3 2", d.capped, d.expired, d.skipped, d.total())
	}
	// Children of a later find are counted as skipped, never built.
	d.expand(job{domain: "p0.example.com", depth: 1})
	if d.skipped != 8 || len(d.frontier) != 0 {
		t.Errorf("skipped %d frontier %d after a capped expand, want 8 and 0", d.skipped, len(d.frontier))
	}
}

func TestDispatcherResumeFrom(t *testing.T) {
	d := testDispatcher(Config{Entries: []string{"a", "b", "c", "d"}, ResumeFrom: 2}, 1)
	if d.watermark != 2 || d.total() != 2 {
		t.Fatalf("watermark %d total %d, want 2 and 2", d.watermark, d.total())
	}
	if got := drain(d); !slices.Equal(got, []string{"c.example.com", "d.example.com"}) {
		t.Fatalf("jobs %v", got)
	}
	// Entries before the resume point are ignored if reported again.
	d.settle(0)
	if d.watermark != 2 {
		t.Errorf("watermark %d, want 2", d.watermark)
	}
}

func TestDispatcherResumeParents(t *testing.T) {
	d := testDispatcher(Config{
		Entries: []string{"x"}, Recursive: true,
		ResumeParents: []string{"dev.example.com.", "a.b.c.example.com", "other.org"},
	}, 3)
	// dev (depth 1) is re-expanded; a.b.c (depth 3) is at the depth limit,
	// and other.org is outside the target.
	if got := drain(d); !slices.Equal(got, []string{"x.example.com", "x.dev.example.com"}) {
		t.Errorf("jobs %v", got)
	}
}

func TestDispatcherExpandsAndDedupesChildren(t *testing.T) {
	d := testDispatcher(Config{Entries: []string{"a", "b"}, Recursive: true}, 3)
	drain(d)
	d.expand(job{domain: "a.example.com", depth: 1})
	d.expand(job{domain: "a.example.com", depth: 1}) // reported twice
	got := drain(d)
	if want := []string{"a.a.example.com", "b.a.example.com"}; !slices.Equal(got, want) {
		t.Errorf("children %v, want %v", got, want)
	}
	if d.total() != 4 {
		t.Errorf("total %d, want 4", d.total())
	}
}

func TestDispatcherDeadline(t *testing.T) {
	past := Config{Entries: makeEntries(4), Deadline: time.Now().Add(-time.Second)}
	d := testDispatcher(past, 1)
	if got := drain(d); len(got) != 0 || !d.expired || d.skipped != 4 {
		t.Errorf("jobs %v expired %v skipped %d, want none, true, 4", got, d.expired, d.skipped)
	}

	// The timer fires with a job admitted but not yet handed out.
	d = testDispatcher(Config{Entries: makeEntries(4)}, 1)
	if _, ok := d.next(); !ok {
		t.Fatal("no job")
	}
	d.expire(1)
	if !d.expired || d.skipped != 4 || d.admitted != 0 || d.total() != 0 {
		t.Errorf("expired %v skipped %d admitted %d total %d, want true 4 0 0", d.expired, d.skipped, d.admitted, d.total())
	}

	// A worker skips a job it took after the deadline.
	d = testDispatcher(Config{Entries: makeEntries(3)}, 1)
	d.next()
	d.pending = 1
	d.complete(completion{root: 0, skipped: true})
	if !d.expired || d.skipped != 3 || d.pending != 0 || d.watermark != 0 {
		t.Errorf("expired %v skipped %d pending %d watermark %d, want true 3 0 0", d.expired, d.skipped, d.pending, d.watermark)
	}
}
