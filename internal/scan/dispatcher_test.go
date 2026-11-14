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

// A recursive scan can reach one name twice, so it dedupes; a flat scan
// relies on its entries being unique already and keeps no visited set
// (#248).
func TestDispatcherDedupesAndSettlesDuplicates(t *testing.T) {
	if flat := testDispatcher(Config{Entries: []string{"www"}}, 1); flat.visited != nil {
		t.Error("a non-recursive scan allocated a visited set")
	}
	d := testDispatcher(Config{Entries: []string{"www", "mail", "www", "api"}, Recursive: true}, 1)
	got := drain(d)
	if want := []string{"www.example.com", "mail.example.com", "api.example.com"}; !slices.Equal(got, want) {
		t.Fatalf("jobs %v, want %v", got, want)
	}
	// The duplicate (index 2) settled when it was skipped; the others settle
	// as they complete, in any order.
	for _, root := range []int{3, 0} {
		d.complete(completion{root: root, finished: true})
	}
	if d.watermark != 1 {
		t.Errorf("watermark %d, want 1 (entry 1 not yet done)", d.watermark)
	}
	d.complete(completion{root: 1, finished: true})
	if d.watermark != 4 {
		t.Errorf("watermark %d, want 4", d.watermark)
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
