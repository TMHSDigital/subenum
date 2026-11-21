package scan

import (
	"context"
	"sort"
	"sync"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// inconclusive reports whether a lookup outcome leaves the name's existence
// unknown: a timeout, a refusal or another failure (#217).
func inconclusive(o dns.Outcome) bool {
	return o == dns.OutcomeTimeout || o == dns.OutcomeRefused || o == dns.OutcomeOther
}

// pendingLookup is a name whose lookup was inconclusive, and that outcome.
// A depth-1 name is kept as its index into cfg.Entries and rebuilt on
// demand, so the list does not keep the job's name string alive (#300);
// only a recursive child, which has no such index, keeps its name.
type pendingLookup struct {
	name     string // a recursive child's full name; "" for a depth-1 name
	root     int    // index into cfg.Entries for a depth-1 name, else -1
	outcome  dns.Outcome
	prior    bool // from Config.RetryPrior: an earlier part of a resumed scan looked it up (#315)
	retried  bool // the retry pass looked it up again, still without an answer
	followed bool // a FollowRecords target (#432), so a find keeps that source
}

// Pending is a name whose lookup was inconclusive and that the retry pass
// has not looked up again yet, with the outcome it got (#315).
type Pending struct {
	Name    string
	Outcome dns.Outcome
}

// pendingOf is the list entry for job j, whose lookup ended in o.
func pendingOf(j job, o dns.Outcome) pendingLookup {
	if j.root >= 0 {
		return pendingLookup{root: j.root, outcome: o}
	}
	return pendingLookup{name: j.domain, root: -1, outcome: o, followed: j.followed}
}

// domain is the name that was looked up.
func (p pendingLookup) domain(cfg *Config) string {
	if p.root >= 0 {
		return cfg.roots().at(p.root) + "." + cfg.Domain
	}
	return p.name
}

// pendingList collects the inconclusive lookups of a scan, for the retry
// pass and Stats.Inconclusive (#217). Workers add to it concurrently. A nil
// list collects nothing: the scan has no reader for the names (#300).
type pendingList struct {
	mu    sync.Mutex
	items []pendingLookup
}

func (l *pendingList) add(it pendingLookup) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.items = append(l.items, it)
	l.mu.Unlock()
}

// take empties the list and returns what it held.
func (l *pendingList) take() []pendingLookup {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	items := l.items
	l.items = nil
	return items
}

// recordRepeat notes how job j ended, for Stats.Repeat.
func (s *scanState) recordRepeat(j job, code uint8) {
	if j.root < 0 {
		s.deep[code].Add(1)
		return
	}
	if i := j.root - s.rootStart; i >= 0 && i < len(s.rootOutcome) {
		s.rootOutcome[i] = code
	}
}

// moveRepeat moves a name the retry pass recovered to its new repeat code,
// as retry moves it between the counters (#374): a resume that looks it up
// again must take it off the counter it ends in now. A name from an earlier
// part (RetryPrior) is not looked up again.
func (s *scanState) moveRepeat(it pendingLookup, code uint8) {
	switch {
	case it.prior:
	case it.root < 0:
		s.deep[repeatCode(it.outcome)].Add(-1)
		s.deep[code].Add(1)
	default:
		s.recordRepeat(job{root: it.root}, code)
	}
}

// repeated reports whether a resume from the scan's RootDone looks up the
// inconclusive name it again.
func (s *scanState) repeated(it pendingLookup) bool {
	return !it.prior && (it.root < 0 || int64(it.root) >= s.stats.rootDone.Load())
}

// finishPending empties the pending list into snap: the inconclusive names
// and the repeated ones among them, and the names a resumed scan's retry
// pass must still look up.
func (s *scanState) finishPending(snap *Stats, repeat *Repeat) {
	cfg := &s.cfg
	items := s.pending.take()
	if cfg.ListInconclusive {
		all := make([]string, 0, len(items))
		for _, it := range items {
			name := it.domain(cfg)
			all = append(all, name)
			if s.repeated(it) {
				repeat.Inconclusive = append(repeat.Inconclusive, name)
			}
		}
		sort.Strings(all)
		sort.Strings(repeat.Inconclusive)
		snap.Inconclusive = all
	}
	if cfg.RetryInconclusive {
		for _, it := range items {
			if !it.retried && !s.repeated(it) {
				snap.Pending = append(snap.Pending, Pending{Name: it.domain(cfg), Outcome: it.outcome})
			}
		}
	}
}

// repeat tallies Stats.Repeat once every worker has exited. Every exclusion
// is repeated but those of entries before RootDone.
func (s *scanState) repeat() Repeat {
	var n [repeatCodes]int64
	for code := range n {
		n[code] = s.deep[code].Load()
	}
	from := int(s.stats.rootDone.Load()) - s.rootStart
	var kept int64
	for i, code := range s.rootOutcome {
		switch {
		case i >= from:
			n[code]++
		case code == repeatExcluded:
			kept++
		}
	}
	r := Repeat{Found: n[repeatFound], NXDomain: n[repeatNXDomain], Timeout: n[repeatTimeout],
		Refused: n[repeatRefused], Other: n[repeatOther], WildcardFiltered: n[repeatWildcard]}
	r.Processed = r.Found + r.NXDomain + r.Timeout + r.Refused + r.Other + r.WildcardFiltered
	r.Excluded = max(s.stats.excluded.Load()-kept, 0)
	return r
}

// retryPending is the RetryInconclusive pass (#217): once every candidate
// has been tried, each inconclusive lookup is tried once more against the
// trusted resolver by up to workers goroutines. It does not run after the
// reliability guard aborted the scan, after an interrupt or once the
// Deadline has passed; names it does not get to stay inconclusive.
func (s *scanState) retryPending(ctx context.Context, workers int) {
	if ctx.Err() != nil || s.stats.aborted.Load() || s.cfg.pastDeadline() {
		return
	}
	// The list keeps the names the pass does not get to, for Stats.Pending,
	// and the ones still unanswered after it when something lists them.
	items := s.pending.take()
	ch := make(chan pendingLookup)
	var wg sync.WaitGroup
	for range min(workers, len(items)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range ch {
				s.retry(ctx, it)
			}
		}()
	}
	for i, it := range items {
		if ctx.Err() != nil || s.cfg.pastDeadline() {
			for _, rest := range items[i:] {
				s.pending.add(rest)
			}
			break
		}
		ch <- it
	}
	close(ch)
	wg.Wait()
}

// retry looks an inconclusive name up once more. An answer, positive or
// negative, replaces the first outcome in the counters; a name found is
// reported (unless it is a wildcard answer) but not expanded. A name still
// without an answer keeps its first outcome and stays pending.
func (s *scanState) retry(ctx context.Context, it pendingLookup) {
	cfg, st := s.cfg, &s.stats
	if err := s.limiter.Wait(ctx); err != nil {
		s.pending.add(it)
		return
	}
	name := it.domain(&s.cfg)
	records, outcome, partial := cfg.resolvePartial(ctx, name, cfg.logf())
	if outcome = settle(ctx, outcome); outcome == dns.OutcomeCanceled {
		s.pending.add(it)
		return
	}
	st.retried.Add(1)
	if inconclusive(outcome) {
		if cfg.ListInconclusive {
			it.retried = true
			s.pending.add(it)
		}
		return
	}
	st.recovered.Add(1)
	st.counter(it.outcome).Add(-1)
	if outcome == dns.OutcomeFound && isWildcardAnswer(ctx, cfg, s.fp, name, records) {
		st.wildcardFiltered.Add(1)
		s.moveRepeat(it, repeatWildcard)
		return
	}
	st.add(outcome)
	s.moveRepeat(it, repeatCode(outcome))
	if outcome == dns.OutcomeFound {
		s.report(ctx, name, records, partial, it.followed)
	}
}
