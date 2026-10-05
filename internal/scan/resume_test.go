package scan

import (
	"context"
	"maps"
	"slices"
	"testing"
)

// runCollect runs cfg, cancelling once stopAfter results have arrived
// (0 = never), and returns the found names and the final stats.
func runCollect(t *testing.T, cfg Config, stopAfter int) (map[string]bool, Stats) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan Event, 64)
	go Run(ctx, cfg, events)
	found := map[string]bool{}
	var stats Stats
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			found[ev.Domain] = true
			if stopAfter > 0 && len(found) == stopAfter {
				cancel()
			}
		case EventDone:
			stats = ev.Stats
		}
	}
	return found, stats
}

// TestResumeMatchesUninterruptedRun is #73's done-when at the scan level:
// interrupting a simulated scan and resuming from its RootDone yields the
// same result set as an uninterrupted run with the same seed.
func TestResumeMatchesUninterruptedRun(t *testing.T) {
	for _, recursive := range []bool{false, true} {
		t.Run(map[bool]string{false: "flat", true: "recursive"}[recursive], func(t *testing.T) {
			cfg := Config{
				Domain: "example.com", Entries: makeEntries(400), Concurrency: 8,
				Simulate: true, HitRate: 10, Seed: 42, Attempts: 1,
				Recursive: recursive, Depth: 2,
			}
			want, _ := runCollect(t, cfg, 0)

			partial, stats := runCollect(t, cfg, len(want)/2)
			// A recursive scan settles every depth-1 entry before most of its
			// hits (children) arrive, so RootDone may already be the end; the
			// rest of the work is then carried by ResumeParents.
			if len(partial) >= len(want) || stats.RootDone <= 0 || (!recursive && stats.RootDone >= int64(len(cfg.Entries))) {
				t.Fatalf("interrupt did not land mid-scan: %d/%d results, RootDone %d", len(partial), len(want), stats.RootDone)
			}

			resumed := cfg
			resumed.ResumeFrom = int(stats.RootDone)
			resumed.ResumeParents = slices.Collect(maps.Keys(partial))
			rest, _ := runCollect(t, resumed, 0)

			union := maps.Clone(partial)
			maps.Copy(union, rest)
			if !maps.Equal(union, want) {
				missing := 0
				for n := range want {
					if !union[n] {
						missing++
					}
				}
				t.Fatalf("resumed union has %d names, uninterrupted %d (%d missing)", len(union), len(want), missing)
			}
		})
	}
}
