package cli

import (
	"context"
	"sync"

	"github.com/TMHSDigital/subenum/internal/scan"
)

// targetLookup is one target's passive-source lookups and its zone transfer
// or NSEC walk, run in a goroutine. The lines they print are held until the
// target starts, so a lookup fetched ahead prints where it would have run
// (#365).
type targetLookup struct {
	done        chan struct{}
	sources     []targetSource
	axfr        targetAXFR
	sourceLines heldLines // the sources' warnings and notes
	axfrLines   heldLines // the zone transfer's and walk's lines, printed after the sources'
}

// startLookup starts target's lookups. The zone transfer runs while the
// passive sources are asked: they are independent, and a source can take
// tens of seconds. A target -exclude rules out gets neither (#372).
func (s *session) startLookup(ctx context.Context, target string, saved *resumeTarget) *targetLookup {
	l := &targetLookup{done: make(chan struct{})}
	inScope := !scan.TargetOutOfScope(s.in.excludes, target)
	go func() {
		defer close(l.done)
		if !inScope {
			return
		}
		var transfer sync.WaitGroup
		if s.f.axfr || s.f.nsecWalk {
			transfer.Go(func() {
				l.axfr = zoneTransfer(ctx, s.f, s.a.transferPort(), target, saved, l.axfrLines.Info, scan.Excluder(s.in.excludes), s.in.deadline)
			})
		}
		l.sources = passiveNames(ctx, s.in.sources, target, saved, l.sourceLines.Info, s.a.sourceURLs)
		transfer.Wait()
	}()
	return l
}

// wait blocks until the lookup has finished.
func (l *targetLookup) wait() { <-l.done }

// lookahead holds the lookup started for the next -dL target while the
// current one scans (#365). There is at most one, started only once the
// current target's own lookup finished, so a source such as crt.sh still
// gets one request at a time. Nothing of it reaches the resume state unless
// its target starts: a target that never does (an interrupt, a resolver
// abort) has no result to save.
type lookahead struct {
	ctx    context.Context // cancelled when the run's targets end
	target int
	lookup *targetLookup
}

// take returns the lookup fetched ahead for target i, if there is one.
func (la *lookahead) take(i int) *targetLookup {
	if la == nil || la.lookup == nil || la.target != i {
		return nil
	}
	l := la.lookup
	la.lookup = nil
	return l
}

// discard waits for a lookup no target took, once its context is
// cancelled, so no goroutine outlives the run.
func (la *lookahead) discard() {
	if la.lookup != nil {
		la.lookup.wait()
		la.lookup = nil
	}
}

// fetchAhead starts target i's lookups, if it has any to do and would be
// scanned: a target without wordlist entries is not.
func (s *session) fetchAhead(la *lookahead, i int) {
	if la == nil || i >= len(s.targets) || la.ctx.Err() != nil {
		return
	}
	if len(s.in.sources) == 0 && !s.f.axfr && !s.f.nsecWalk {
		return
	}
	target := s.targets[i]
	if entries, _, _ := s.words.For(target); len(entries) == 0 {
		return
	}
	la.target, la.lookup = i, s.startLookup(la.ctx, target, s.resume.target(target))
}
