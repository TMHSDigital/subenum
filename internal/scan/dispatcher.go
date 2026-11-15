package scan

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// dispatcher owns candidate generation for one scan (#159): the expansion
// queue, the expanded and visited sets (loop and duplicate protection), the resume
// watermark, the -max-queries and -max-duration budgets, and the count of
// dispatched jobs not yet completed. Its methods are plain state changes,
// called only from run's goroutine (or a test), so they need no locking.
//
// Candidates are generated lazily. The queue holds expansions (a parent plus
// a cursor into Entries) rather than one job per name, so depth-1 names are
// built only as they are dispatched and a found parent costs one enqueue
// instead of len(Entries) (#49). Once a budget is reached the remaining
// candidates are counted, never built or recorded (#51).
type dispatcher struct {
	cfg Config
	n   int // len(cfg.Entries)

	// A recursive scan dedupes by parent: expanded holds every parent queued
	// for expansion, so one found twice (a resumed parent found again) is
	// expanded once. With single-label entries that is enough, since a name
	// then has one (entry, parent) pair. Only multi-label entries can reach
	// one name through two parents ("a.b" under the root, "a" under
	// "b.root"), and only then is visited, the set of generated candidates,
	// kept (#301). Both are nil for a non-recursive scan.
	expanded  map[string]struct{}
	visited   map[string]struct{}
	frontier  []expansion
	head      int // first unconsumed expansion in frontier
	remaining int // candidates not yet generated

	// Resume point: rootDone[i-start] is set once entry i is settled (looked
	// up, or skipped as a duplicate or out of scope); watermark is the first
	// index not yet settled.
	start     int
	rootDone  []bool
	watermark int

	admitted int // jobs handed out (or held) and counted in the total
	skipped  int // candidates a budget kept from being tested
	excluded int // candidates -exclude kept out of scope
	capped   bool
	expired  bool // the budget that capped admission was the deadline
	pending  int  // dispatched jobs not yet completed

	// rootOutcome is the scan's per-entry repeat codes from start on
	// (scanState.rootOutcome); the dispatcher marks the entries out of
	// scope, the workers the rest. Nil in tests that need no Stats.Repeat.
	rootOutcome []uint8
}

// visitedSet is the dispatcher's set of generated candidates: a map for a
// recursive scan whose entries include a multi-label one, nil otherwise.
func visitedSet(recursive bool, entries []string) map[string]struct{} {
	if !recursive {
		return nil
	}
	for _, e := range entries {
		if strings.Contains(e, ".") {
			return make(map[string]struct{}, len(entries))
		}
	}
	return nil
}

func newDispatcher(cfg Config, maxDepth int) *dispatcher {
	n := len(cfg.Entries)
	start := min(max(cfg.ResumeFrom, 0), n)
	d := &dispatcher{
		cfg: cfg,
		n:   n,
		// Entries are unique (every caller deduplicates them), so only a
		// recursive scan with multi-label entries, whose levels can reach
		// one name twice, needs to remember what it visited. Without it a
		// multi-million-entry list skips a map as large as the list (#248),
		// and a recursive scan one that grows with every candidate (#301).
		visited:   visitedSet(cfg.Recursive, cfg.Entries),
		frontier:  []expansion{{parent: cfg.Domain, depth: 1, next: start}},
		remaining: n - start,
		start:     start,
		rootDone:  make([]bool, n-start),
		watermark: start,
	}
	// Resumed recursive scans re-expand the names found before the
	// interrupt, whose children may not all have been tested (#73). Run
	// passes only the ones a live scan would expand (see gateResumeParents).
	if cfg.Recursive {
		if d.cfg.resumeDepth == nil {
			d.cfg.resumeDepth = resumeDepths(cfg)
		}
		d.expanded = make(map[string]struct{})
		for _, p := range cfg.ResumeParents {
			if name, depth, ok := resumeParent(d.cfg, p, maxDepth); ok && d.markExpanded(name) {
				d.frontier = append(d.frontier, expansion{parent: name, depth: depth + 1})
				d.remaining += n
			}
		}
	}
	return d
}

// markExpanded records parent as queued for expansion and reports whether it
// was new. A non-recursive scan never expands, so it keeps no record.
func (d *dispatcher) markExpanded(parent string) bool {
	if d.expanded == nil {
		return true
	}
	if _, dup := d.expanded[parent]; dup {
		return false
	}
	d.expanded[parent] = struct{}{}
	return true
}

// resumeParent normalizes a name found before an interrupt and reports its
// depth below the target and whether a resumed scan may expand it: it must
// lie under the target and above the depth limit. The depth is the recursion
// level resumeDepths found; a name it could not place keeps its label count.
func resumeParent(cfg Config, p string, maxDepth int) (name string, depth int, ok bool) {
	name = strings.ToLower(strings.TrimSuffix(p, "."))
	if !strings.HasSuffix(name, "."+cfg.Domain) {
		return name, 0, false
	}
	depth, known := cfg.resumeDepth[name]
	if !known {
		depth = strings.Count(name, ".") - strings.Count(cfg.Domain, ".")
	}
	return name, depth, depth >= 1 && depth < maxDepth
}

// resumeDepths finds the recursion level of each resumed parent, by name
// (#315). A live scan's level is not the label count: an entry may hold
// several labels ("dev.api"), and every entry is level 1. A parent is level
// 1 when its name relative to the target is an entry, else one more than the
// lowest level of a resumed parent it is an entry under, which is the level
// a live scan, breadth first, reaches it at. Only the prefixes of the
// parents are looked up in Entries, so no set as large as the wordlist is
// built.
func resumeDepths(cfg Config) map[string]int {
	if !cfg.Recursive || len(cfg.ResumeParents) == 0 {
		return nil
	}
	suffix := "." + cfg.Domain
	parents := map[string]bool{} // relative to the target
	isEntry := map[string]bool{} // every way to split a parent, entry first
	for _, p := range cfg.ResumeParents {
		rel, ok := strings.CutSuffix(strings.ToLower(strings.TrimSuffix(p, ".")), suffix)
		if !ok || rel == "" {
			continue
		}
		parents[rel] = true
		isEntry[rel] = false
		for i := range len(rel) {
			if rel[i] == '.' {
				isEntry[rel[:i]] = false
			}
		}
	}
	for _, e := range cfg.Entries {
		if _, ok := isEntry[e]; ok {
			isEntry[e] = true
		}
	}
	level := make(map[string]int, len(parents)) // 0: no way to reach it
	var find func(rel string) int
	find = func(rel string) int {
		if d, ok := level[rel]; ok {
			return d
		}
		best := 0
		if isEntry[rel] {
			best = 1
		}
		for i := 0; i < len(rel) && best != 1; i++ {
			if rel[i] != '.' || !isEntry[rel[:i]] || !parents[rel[i+1:]] {
				continue
			}
			if d := find(rel[i+1:]); d > 0 && (best == 0 || d+1 < best) {
				best = d + 1
			}
		}
		level[rel] = best
		return best
	}
	depths := make(map[string]int, len(parents))
	for rel := range parents {
		if d := find(rel); d > 0 {
			depths[rel+suffix] = d
		}
	}
	return depths
}

// settle marks wordlist entry i as done and advances the resume watermark.
// i is -1 for jobs below depth 1, which do not affect it.
func (d *dispatcher) settle(i int) {
	if i < d.start {
		return
	}
	d.rootDone[i-d.start] = true
	for d.watermark < d.n && d.rootDone[d.watermark-d.start] {
		d.watermark++
	}
}

// stopAdmitting ends admission for a budget: every candidate not yet
// generated, and every child a later find would add, is skipped. Candidates
// that -exclude, or a recursive scan's visited set, would have kept out are
// counted as they would have been, not as skipped, so a budget that ran out
// only past them still leaves the verdict complete (#238). Without
// exclusions a cap stays O(1), and with them no candidate is built (see
// countUnbuilt); only a visited set (multi-label entries in a recursive
// scan) needs every remaining candidate walked (#301).
func (d *dispatcher) stopAdmitting() {
	switch {
	case d.visited == nil && d.cfg.scope.empty():
		d.skipped += d.remaining
	case d.visited == nil:
		d.countUnbuilt()
	default:
		for _, e := range d.frontier[d.head:] {
			for i := e.next; i < d.n; i++ {
				entry := d.cfg.Entries[i]
				name := entry + "." + e.parent
				if d.visited != nil {
					key := entry
					if e.depth > 1 {
						key = name[:len(name)-len(d.cfg.Domain)-1]
					}
					if _, dup := d.visited[key]; dup {
						continue
					}
				}
				if d.cfg.scope.excluded(name) {
					d.excluded++
				} else {
					d.skipped++
				}
			}
		}
	}
	d.remaining = 0
	d.capped = true
	d.frontier, d.head = nil, 0
}

// countUnbuilt splits the candidates not yet generated into excluded and
// skipped without building them, for a scan with no visited set (so every
// entry is a single label). An expansion whose parent's subtree is excluded
// is excluded whole. Otherwise only an exact pattern can exclude a child,
// and only the child made of its first label under its parent, so one pass
// over the entries finds where those labels sit, and each expansion then
// checks the patterns directly below its parent against its cursor.
func (d *dispatcher) countUnbuilt() {
	s := d.cfg.scope
	labels := make(map[string][]string) // parent -> first labels of the exact patterns below it
	index := make(map[string]int)       // those labels -> their index in Entries, -1 if absent
	for pattern := range s.exact {
		if label, parent, ok := strings.Cut(pattern, "."); ok {
			labels[parent] = append(labels[parent], label)
			index[label] = -1
		}
	}
	if len(index) > 0 {
		for i, entry := range d.cfg.Entries {
			if _, ok := index[entry]; ok {
				index[entry] = i
			}
		}
	}
	for _, e := range d.frontier[d.head:] {
		left := d.n - e.next
		if s.subtreeExcluded(e.parent) {
			d.excluded += left
			continue
		}
		out := 0
		for _, label := range labels[e.parent] {
			if index[label] >= e.next {
				out++
			}
		}
		d.excluded += out
		d.skipped += left - out
	}
}

// total is the progress total: jobs admitted plus candidates not yet
// generated, at most -max-queries.
func (d *dispatcher) total() int64 {
	t := d.admitted + d.remaining
	if d.cfg.MaxQueries > 0 && t > d.cfg.MaxQueries {
		t = d.cfg.MaxQueries
	}
	return int64(t)
}

// next generates the next admissible job, if any.
func (d *dispatcher) next() (job, bool) {
	for d.head < len(d.frontier) {
		e := &d.frontier[d.head]
		if e.next == d.n {
			d.head++
			// Compact only once the consumed prefix is at least half the
			// slice, so each element is copied O(1) times.
			if d.head == len(d.frontier) {
				d.frontier, d.head = d.frontier[:0], 0
			} else if d.head*2 >= len(d.frontier) {
				d.frontier, d.head = append(d.frontier[:0], d.frontier[d.head:]...), 0
			}
			continue
		}
		if d.cfg.pastDeadline() {
			d.expired = true
			d.stopAdmitting()
			return job{}, false
		}
		if d.cfg.MaxQueries > 0 && d.admitted >= d.cfg.MaxQueries {
			d.stopAdmitting()
			return job{}, false
		}
		entry := d.cfg.Entries[e.next]
		e.next++
		d.remaining--
		name := entry + "." + e.parent
		root := -1
		if e.depth == 1 {
			root = e.next - 1
		}
		if d.visited != nil {
			// Key by the name relative to the root domain. For depth 1 that
			// is the entry itself, so no extra string is retained.
			key := entry
			if e.depth > 1 {
				key = name[:len(name)-len(d.cfg.Domain)-1]
			}
			if _, dup := d.visited[key]; dup {
				d.settle(root)
				continue
			}
			d.visited[key] = struct{}{}
		}
		if d.cfg.scope.excluded(name) {
			d.excluded++
			if root >= 0 && d.rootOutcome != nil {
				d.rootOutcome[root-d.start] = repeatExcluded
			}
			d.settle(root)
			continue
		}
		d.admitted++
		return job{domain: name, depth: e.depth, root: root}, true
	}
	return job{}, false
}

// expand queues the children of a found parent, unless a budget has stopped
// admission or every child would be out of scope; then they are only counted.
// A parent already queued (a resumed one found again) adds nothing.
func (d *dispatcher) expand(parent job) {
	if !d.markExpanded(parent.domain) {
		return
	}
	switch {
	// An excluded subtree is excluded whether or not a budget has run out,
	// as countUnbuilt counts it, so it cannot lower the verdict (#238).
	case d.cfg.scope.subtreeExcluded(parent.domain):
		d.excluded += d.n
	case d.capped:
		d.skipped += d.n
	default:
		d.frontier = append(d.frontier, expansion{parent: parent.domain, depth: parent.depth + 1})
		d.remaining += d.n
	}
}

// expire applies the deadline when its timer fires (#190). held is how many
// jobs were admitted but not yet handed to a worker; they are skipped, even
// when -max-queries stopped admission first, so tested plus skipped still
// adds up to every candidate (#317).
func (d *dispatcher) expire(held int) {
	d.admitted -= held
	d.skipped += held
	if held > 0 {
		d.expired = true
	}
	if d.capped {
		return
	}
	d.expired = true
	d.stopAdmitting()
}

// maxChunk caps how many jobs a worker takes at once (#184).
const maxChunk = 8

// nextChunk admits up to one job per worker's share of what is left, at
// most maxChunk: handing jobs out in chunks cuts the channel traffic per
// job, and sizing the chunk by what is left keeps a short wordlist spread
// over every worker.
func (d *dispatcher) nextChunk(workers int) []job {
	size := min(maxChunk, max(1, d.remaining/max(1, workers)))
	var chunk []job
	for len(chunk) < size {
		j, ok := d.next()
		if !ok {
			break
		}
		chunk = append(chunk, j)
	}
	return chunk
}

// complete records a worker's report on a dispatched job.
func (d *dispatcher) complete(c completion) {
	d.pending--
	if c.skipped {
		// Taken after the deadline and never looked up: the time budget
		// skipped it, even when -max-queries had already stopped admission.
		d.skipped++
		d.admitted--
		d.expired = true
		if !d.capped {
			d.stopAdmitting()
		}
	}
	if c.finished {
		d.settle(c.root)
	}
}

// completeAll records one worker's report on a chunk.
func (d *dispatcher) completeAll(batch []completion) {
	for _, c := range batch {
		d.complete(c)
	}
}

// finish stores the dispatcher's counts in stats and announces skipped
// candidates. A deadline that left nothing untested changed nothing, so it
// does not mark the scan expired.
func (d *dispatcher) finish(ctx context.Context, stats *counters, events chan<- Event) {
	stats.skipped.Store(int64(d.skipped))
	stats.rootDone.Store(int64(d.watermark))
	stats.excluded.Store(int64(d.excluded))
	d.expired = d.expired && d.skipped > 0
	stats.expired.Store(d.expired)
	if d.skipped == 0 {
		return
	}
	msg := fmt.Sprintf("query cap reached ({max_queries} %d); skipped %d additional jobs", d.cfg.MaxQueries, d.skipped)
	switch {
	case d.expired && d.admitted == 0:
		msg = fmt.Sprintf("time budget reached ({max_duration}) before any name was tested; skipped %d jobs. Raise {max_duration}", d.skipped)
	case d.expired:
		msg = fmt.Sprintf("time budget reached ({max_duration}); skipped %d additional jobs", d.skipped)
	}
	select {
	case events <- Event{Kind: EventNotice, Notice: NoticeCap, Message: msg}:
	case <-ctx.Done():
	}
}

// run hands jobs to workers, in chunks (see nextChunk), until no candidate
// is left and every dispatched job has completed, or ctx is cancelled; then
// it closes jobs. Workers send found parents on enqueue (before reporting on
// completed), and run expands them. total receives the progress total as it
// changes.
func (d *dispatcher) run(ctx context.Context, workers int, jobs chan<- []job, enqueue <-chan job, completed <-chan []completion,
	total *atomic.Int64, stats *counters, events chan<- Event) {
	defer close(jobs)
	// The deadline timer wakes the dispatcher while it waits on a busy
	// worker pool, so the budget holds even if no job completes (#190).
	var deadline <-chan time.Time
	if !d.cfg.Deadline.IsZero() {
		timer := time.NewTimer(time.Until(d.cfg.Deadline))
		defer timer.Stop()
		deadline = timer.C
	}
	publish := func() { total.Store(d.total()) }

	var ready []job
	for {
		if len(ready) == 0 {
			ready = d.nextChunk(workers)
			publish()
		}
		if len(ready) == 0 && d.pending == 0 {
			d.finish(ctx, stats, events)
			return
		}
		var out chan<- []job
		if len(ready) > 0 {
			out = jobs
		}
		select {
		case <-ctx.Done():
			// Count the reports already buffered, so an interrupt keeps
			// the resume point as far as the finished jobs allow.
			for drained := false; !drained; {
				select {
				case batch := <-completed:
					d.completeAll(batch)
				default:
					drained = true
				}
			}
			d.finish(ctx, stats, events)
			return
		case parent := <-enqueue:
			d.expand(parent)
			publish()
		case out <- ready:
			d.pending += len(ready)
			ready = nil
		case <-deadline:
			deadline = nil
			d.expire(len(ready))
			ready = nil
			publish()
		case batch := <-completed:
			d.completeAll(batch)
			publish()
		}
	}
}
