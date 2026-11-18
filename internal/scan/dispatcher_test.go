package scan

import (
	"fmt"
	"slices"
	"strings"
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

// TestDispatcherVisitedHoldsOnlyCollidableNames covers #359: one multi-label
// entry no longer makes the set remember every candidate. Only a name with a
// multi-label entry as a prefix ("a.b" in "a.b.c") can be reached twice, so
// only those are recorded, and the duplicate is dropped whichever path
// generates the name first.
func TestDispatcherVisitedHoldsOnlyCollidableNames(t *testing.T) {
	cfg := Config{Entries: []string{"a.b", "a", "b", "c"}, Recursive: true}
	d := testDispatcher(cfg, 3)
	drain(d)
	d.expand(job{domain: "c.example.com", depth: 1})
	drain(d)
	// a.b, then a.b.c from c's children; a, b, c, a.c, b.c, c.c are not kept.
	if len(d.visited) != 2 {
		t.Errorf("visited holds %d names, want 2 (a.b and a.b.c)", len(d.visited))
	}

	// x.a.b.example.com is "x.a" under b.example.com and "x" under
	// a.b.example.com; either expansion may run first.
	entries := []string{"x.a", "x", "a", "b"}
	for _, order := range [][]string{
		{"b.example.com", "a.b.example.com"},
		{"a.b.example.com", "b.example.com"},
	} {
		d := testDispatcher(Config{Entries: entries, Recursive: true}, 3)
		drain(d)
		for _, p := range order {
			d.expand(job{domain: p, depth: strings.Count(p, ".") - 1})
		}
		got := drain(d)
		if n := slices.Index(got, "x.a.b.example.com"); n < 0 || slices.Contains(got[n+1:], "x.a.b.example.com") {
			t.Errorf("order %v: x.a.b.example.com generated %d times in %v, want once",
				order, strings.Count(strings.Join(got, " "), "x.a.b.example.com"), got)
		}
	}
}

// BenchmarkDispatcherRecursiveDotted measures a recursive scan's memory when
// its 100,000 entries include one with a dot, as a CT or Wayback name does
// (#359): the root and ten found parents, 1.1 million candidates.
func BenchmarkDispatcherRecursiveDotted(b *testing.B) {
	entries := append(makeEntries(100_000), "dev.api")
	b.ReportAllocs()
	var d *dispatcher
	for b.Loop() {
		d = testDispatcher(Config{Entries: entries, Recursive: true}, 2)
		for i := range 10 {
			d.expand(job{domain: entries[i] + ".example.com", depth: 1})
		}
		for {
			if _, ok := d.next(); !ok {
				break
			}
		}
	}
	b.ReportMetric(float64(len(d.visited)), "visited")
}

// TestCapCountsRepeatsWithoutWalking covers #365: with no exclusions, a
// budget in a recursive scan with multi-label entries walks only the entries
// that can begin a repeat, and still counts every name the scan with no
// budget would generate exactly once, whichever job the budget stops at.
func TestCapCountsRepeatsWithoutWalking(t *testing.T) {
	entries := []string{"a", "b", "c", "a.b", "x", "b.c", "x.a.b", "c.a", "y"}
	parents := []string{"b.example.com", "c.example.com", "a.b.example.com", "b.c.example.com", "a.example.com"}
	run := func(maxQueries int) (admitted int, d *dispatcher) {
		d = testDispatcher(Config{Entries: entries, Recursive: true, MaxQueries: maxQueries}, 3)
		if _, ok := d.next(); !ok {
			t.Fatal("no job")
		}
		for _, p := range parents {
			d.expand(job{domain: p, depth: strings.Count(p, ".") - 1})
		}
		return 1 + len(drain(d)), d
	}
	candidates, all := run(0)
	if all.skipped != 0 || candidates >= len(entries)*(len(parents)+1) {
		t.Fatalf("uncapped: %d candidates, skipped %d; want some repeats dropped and none skipped", candidates, all.skipped)
	}
	for limit := 1; limit < candidates; limit++ {
		admitted, d := run(limit)
		if admitted != limit || !d.capped {
			t.Fatalf("cap %d: admitted %d capped %v", limit, admitted, d.capped)
		}
		if admitted+d.skipped != candidates {
			t.Errorf("cap %d: admitted %d + skipped %d = %d, want %d", limit, admitted, d.skipped, admitted+d.skipped, candidates)
		}
	}

	// The remainder is not built: 10,000 entries under 50 parents cost a few
	// hundred allocations, not one per candidate.
	big := append(makeEntries(10_000), "dev.api")
	allocs := testing.AllocsPerRun(3, func() {
		d := testDispatcher(Config{Entries: big, Recursive: true, MaxQueries: 1}, 2)
		d.next()
		for i := range 50 {
			d.expand(job{domain: big[i] + ".example.com", depth: 1})
		}
		d.next()
	})
	if allocs > 5000 {
		t.Errorf("a capped scan of 500,000 candidates made %.0f allocations, want under 5000", allocs)
	}
}

// BenchmarkCapRecursiveDotted measures a budget reached in a recursive scan
// whose 100,000 entries include one with a dot, with 200 found parents
// queued (#365): 20 million candidates to count.
func BenchmarkCapRecursiveDotted(b *testing.B) {
	entries := append(makeEntries(100_000), "dev.api")
	b.ReportAllocs()
	for b.Loop() {
		d := testDispatcher(Config{Entries: entries, Recursive: true, MaxQueries: 1}, 2)
		d.next()
		for i := range 200 {
			d.expand(job{domain: entries[i] + ".example.com", depth: 1})
		}
		if _, ok := d.next(); ok || !d.capped {
			b.Fatal("the budget did not stop admission")
		}
	}
}

// BenchmarkCapLateParent covers #398: a parent found after the budget
// stopped admission costs the same whatever the wordlist's size, since the
// counters' tables are built once, at the cap.
func BenchmarkCapLateParent(b *testing.B) {
	for _, size := range []int{100_000, 1_000_000} {
		for _, tc := range []struct {
			name    string
			exclude []string
		}{
			{"dotted", nil}, // countUnbuiltRepeats
			{"excluded", []string{"www.a1.example.com"}}, // countUnbuilt
		} {
			entries := makeEntries(size)
			if tc.exclude == nil {
				entries = append(entries, "dev.api")
			}
			b.Run(fmt.Sprintf("%s/%d", tc.name, size), func(b *testing.B) {
				d := testDispatcher(Config{Entries: entries, Recursive: true, MaxQueries: 1, Exclude: tc.exclude}, 2)
				d.next()
				if _, ok := d.next(); ok || !d.capped {
					b.Fatal("the budget did not stop admission")
				}
				i := 0
				for b.Loop() {
					d.expand(job{domain: fmt.Sprintf("p%d.example.com", i), depth: 1})
					i++
				}
			})
		}
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

// TestCapCountsExcludedMultiLabelEntries covers #361: in a flat scan whose
// entries hold several labels, a budget counts the ones -exclude would have
// removed as excluded, not skipped, as generating them would.
func TestCapCountsExcludedMultiLabelEntries(t *testing.T) {
	for _, exclude := range []string{"*.dev.example.com", "a.dev.example.com"} {
		cfg := Config{Entries: []string{"www", "a.dev", "b.dev"}, MaxQueries: 1, Exclude: []string{exclude}}
		full := cfg
		full.MaxQueries = 0
		all := testDispatcher(full, 1)
		candidates := len(drain(all)) + all.excluded

		d := testDispatcher(cfg, 1)
		admitted := len(drain(d))
		if admitted != 1 || d.excluded != all.excluded || d.skipped != candidates-admitted-all.excluded {
			t.Errorf("%s: admitted %d skipped %d excluded %d, want 1, %d and %d",
				exclude, admitted, d.skipped, d.excluded, candidates-1-all.excluded, all.excluded)
		}
	}
}

// TestCapCountsRecursiveMultiLabelRemainderOnce covers #361: when a recursive
// scan with multi-label entries is stopped by a budget, a name the rest of
// the scan would have generated twice ("a.b" under the root, "a" under
// b.example.com) is counted once, so admitted, skipped and excluded add up to
// the candidates the scan with no budget generates.
func TestCapCountsRecursiveMultiLabelRemainderOnce(t *testing.T) {
	for _, exclude := range [][]string{nil, {"a.b.example.com"}, {"*.b.example.com"}} {
		cfg := Config{Entries: []string{"b", "x", "a.b", "a"}, Recursive: true, MaxQueries: 2, Exclude: exclude}
		run := func(cfg Config) (admitted int, d *dispatcher) {
			d = testDispatcher(cfg, 2)
			b, ok := d.next()
			if !ok {
				t.Fatal("no job")
			}
			d.expand(job{domain: b.domain, depth: 1})
			return 1 + len(drain(d)), d
		}
		full := cfg
		full.MaxQueries = 0
		allAdmitted, all := run(full)
		candidates := allAdmitted + all.excluded

		admitted, d := run(cfg)
		if admitted != 2 || !d.capped {
			t.Fatalf("%v: admitted %d capped %v, want 2 and true", exclude, admitted, d.capped)
		}
		if d.excluded != all.excluded || admitted+d.skipped+d.excluded != candidates {
			t.Errorf("%v: skipped %d excluded %d, want %d and %d",
				exclude, d.skipped, d.excluded, candidates-admitted-all.excluded, all.excluded)
		}
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

// TestDispatcherCapThenDeadline covers #317: when -max-queries stops
// admission and the deadline then fires with a chunk still held, the held
// jobs are skipped, so tested plus skipped is every candidate, and the scan
// is marked expired because the time budget skipped admitted work.
func TestDispatcherCapThenDeadline(t *testing.T) {
	d := testDispatcher(Config{Entries: makeEntries(10), MaxQueries: 4}, 1)
	held := drain(d) // the cap admits 4 and skips the other 6
	if len(held) != 4 || !d.capped || d.skipped != 6 {
		t.Fatalf("admitted %d capped %v skipped %d, want 4 true 6", len(held), d.capped, d.skipped)
	}
	d.expire(len(held))
	if d.admitted != 0 || d.skipped != 10 || !d.expired || d.total() != 0 {
		t.Errorf("admitted %d skipped %d expired %v total %d, want 0 10 true 0", d.admitted, d.skipped, d.expired, d.total())
	}

	// A deadline with nothing held after the cap changes nothing.
	d = testDispatcher(Config{Entries: makeEntries(10), MaxQueries: 4}, 1)
	drain(d)
	d.expire(0)
	if d.expired || d.skipped != 6 {
		t.Errorf("empty expire after the cap: expired %v skipped %d, want false 6", d.expired, d.skipped)
	}

	// A worker skips a job after the cap: the time budget skipped it.
	d = testDispatcher(Config{Entries: makeEntries(10), MaxQueries: 4}, 1)
	drain(d)
	d.pending = 1
	d.complete(completion{root: 0, skipped: true})
	if !d.expired || d.skipped != 7 || d.admitted != 3 {
		t.Errorf("skipped job after the cap: expired %v skipped %d admitted %d, want true 7 3", d.expired, d.skipped, d.admitted)
	}
}

// A parent found after a budget stop whose whole subtree is excluded has its
// children counted as excluded, not skipped, as countUnbuilt does, so they
// cannot make a complete scan look incomplete (#238).
func TestCappedExpandOfExcludedSubtree(t *testing.T) {
	d := testDispatcher(Config{Entries: makeEntries(5), MaxQueries: 2, Recursive: true,
		Exclude: []string{"*.p0.example.com"}}, 3)
	drain(d)
	skipped := d.skipped
	d.expand(job{domain: "p0.example.com", depth: 1})
	if d.excluded != 5 || d.skipped != skipped {
		t.Errorf("excluded %d skipped %d, want the 5 children excluded and skipped unchanged at %d", d.excluded, d.skipped, skipped)
	}
}

// TestCappedExpandCountsExcludedChildren covers #393: a parent of a recursive
// scan that is found after a budget stopped admission has the children -exclude
// rules out counted as excluded, not skipped, as stopAdmitting counts them.
func TestCappedExpandCountsExcludedChildren(t *testing.T) {
	entries := makeEntries(10)
	d := testDispatcher(Config{Entries: entries, Recursive: true, MaxQueries: 5,
		Exclude: []string{entries[9] + ".p0.example.com"}}, 2)
	if got := len(drain(d)); got != 5 {
		t.Fatalf("admitted %d, want 5", got)
	}
	if d.skipped != 5 || d.excluded != 0 {
		t.Fatalf("before the late expand: skipped %d excluded %d, want 5 and 0", d.skipped, d.excluded)
	}
	d.expand(job{domain: "p0.example.com", depth: 1})
	// p0's ten children: entries[9].p0 is excluded, the other nine are skipped.
	if d.excluded != 1 || d.skipped != 14 || d.admitted+d.skipped+d.excluded != 20 {
		t.Errorf("after the late expand: admitted %d skipped %d excluded %d, want 5, 14 and 1 (20 candidates)",
			d.admitted, d.skipped, d.excluded)
	}
}

// TestCappedExpandCountsRecursiveRepeatsOnce covers #393: a parent of a
// recursive scan found after a budget stopped admission does not have the
// children another parent already reached counted again, so admitted, skipped
// and excluded still add up to the candidates the scan with no budget
// generates, and an excluded child is excluded whichever parent reaches it.
func TestCappedExpandCountsRecursiveRepeatsOnce(t *testing.T) {
	for _, exclude := range [][]string{nil, {"x.a.b.example.com"}} {
		cfg := Config{Entries: []string{"x", "x.a", "a.b", "b", "y"}, Recursive: true, MaxQueries: 4, Exclude: exclude}
		// The same scan with no budget, expanding both parents.
		full := cfg
		full.MaxQueries = 0
		all := testDispatcher(full, 3)
		roots := len(drain(all))
		all.expand(job{domain: "b.example.com", depth: 1})
		all.expand(job{domain: "a.b.example.com", depth: 1})
		candidates := roots + len(drain(all)) + all.excluded

		d := testDispatcher(cfg, 3)
		admitted := len(drain(d))
		// Both parents resolve after the cap: b first, a.b second, so
		// x.a.b.example.com is reached from both and counted once.
		d.expand(job{domain: "b.example.com", depth: 1})
		d.expand(job{domain: "a.b.example.com", depth: 1})
		if admitted != 4 || !d.capped {
			t.Fatalf("%v: admitted %d capped %v, want 4 and true", exclude, admitted, d.capped)
		}
		if d.skipped != candidates-admitted-all.excluded || d.excluded != all.excluded || admitted+d.skipped+d.excluded != candidates {
			t.Errorf("%v: skipped %d excluded %d, want %d and %d (of %d candidates)",
				exclude, d.skipped, d.excluded, candidates-admitted-all.excluded, all.excluded, candidates)
		}
	}
}
