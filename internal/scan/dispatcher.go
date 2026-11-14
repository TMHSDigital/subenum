package scan

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// dispatcher owns candidate generation for one scan (#159): the expansion
// queue, the visited set (loop and duplicate protection), the resume
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
}

// visitedSet is the dispatcher's visited set: a map for recursive scans,
// nil otherwise.
func visitedSet(recursive bool, n int) map[string]struct{} {
	if !recursive {
		return nil
	}
	return make(map[string]struct{}, n)
}

func newDispatcher(cfg Config, maxDepth int) *dispatcher {
	n := len(cfg.Entries)
	start := min(max(cfg.ResumeFrom, 0), n)
	d := &dispatcher{
		cfg: cfg,
		n:   n,
		// Entries are unique (every caller deduplicates them), so only a
		// recursive scan, whose levels can reach one name twice, needs to
		// remember what it visited. Without it a multi-million-entry list
		// skips a map as large as the list (#248).
		visited:   visitedSet(cfg.Recursive, n),
		frontier:  []expansion{{parent: cfg.Domain, depth: 1, next: start}},
		remaining: n - start,
		start:     start,
		rootDone:  make([]bool, n-start),
		watermark: start,
	}
	// Resumed recursive scans re-expand the names found before the
	// interrupt, whose children may not all have been tested (#73).
	if cfg.Recursive {
		rootLabels := strings.Count(cfg.Domain, ".") + 1
		for _, p := range cfg.ResumeParents {
			p = strings.ToLower(strings.TrimSuffix(p, "."))
			if !strings.HasSuffix(p, "."+cfg.Domain) {
				continue
			}
			if depth := strings.Count(p, ".") + 1 - rootLabels; depth >= 1 && depth < maxDepth {
				d.frontier = append(d.frontier, expansion{parent: p, depth: depth + 1})
				d.remaining += n
			}
		}
	}
	return d
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
// exclusions that walk is not needed, and a cap stays O(1).
func (d *dispatcher) stopAdmitting() {
	if d.cfg.scope.empty() && d.visited == nil {
		d.skipped += d.remaining
	} else {
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
		// Key by the name relative to the root domain. For depth 1 that is
		// the entry itself, so no extra string is retained.
		key := entry
		if e.depth > 1 {
			key = name[:len(name)-len(d.cfg.Domain)-1]
		}
		root := -1
		if e.depth == 1 {
			root = e.next - 1
		}
		if d.visited != nil {
			if _, dup := d.visited[key]; dup {
				d.settle(root)
				continue
			}
			d.visited[key] = struct{}{}
		}
		if d.cfg.scope.excluded(name) {
			d.excluded++
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
func (d *dispatcher) expand(parent job) {
	switch {
	case d.capped:
		d.skipped += d.n
	case d.cfg.scope.subtreeExcluded(parent.domain):
		d.excluded += d.n
	default:
		d.frontier = append(d.frontier, expansion{parent: parent.domain, depth: parent.depth + 1})
		d.remaining += d.n
	}
}

// expire applies the deadline when its timer fires (#190). held is how many
// jobs were admitted but not yet handed to a worker; they are skipped.
func (d *dispatcher) expire(held int) {
	if d.capped {
		return
	}
	d.expired = true
	d.admitted -= held
	d.skipped += held
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
		// Taken after the deadline and never looked up.
		d.skipped++
		d.admitted--
		if !d.capped {
			d.expired = true
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
	if d.expired {
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
	total *int64, stats *counters, events chan<- Event) {
	defer close(jobs)
	// The deadline timer wakes the dispatcher while it waits on a busy
	// worker pool, so the budget holds even if no job completes (#190).
	var deadline <-chan time.Time
	if !d.cfg.Deadline.IsZero() {
		timer := time.NewTimer(time.Until(d.cfg.Deadline))
		defer timer.Stop()
		deadline = timer.C
	}
	publish := func() { atomic.StoreInt64(total, d.total()) }

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
