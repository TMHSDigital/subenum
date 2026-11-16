package scan

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
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
			found[ev.Result.Subdomain] = true
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
			if !recursive {
				// Unpaced, a flat simulated scan can finish before the
				// interrupt lands; 2000 names/s gives it ~0.2s to run.
				cfg.Rate = 2000
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

// TestResumeMultiLabelParentDepth covers #315: a parent found through a
// multi-label entry is at level 1 whatever its label count, so a resumed
// scan expands it, and its children, as far as an uninterrupted run does.
func TestResumeMultiLabelParentDepth(t *testing.T) {
	zone := map[string]bool{"dev.api.example.com": true, "x.dev.api.example.com": true, "x.x.dev.api.example.com": true}
	addr, stop := startUDPDNS(t, func(name string, _ uint16) ([4]byte, bool) {
		return [4]byte{192, 0, 2, 5}, zone[name]
	})
	defer stop()
	for _, tc := range []struct {
		depth   int
		parents []string
	}{
		{2, []string{"dev.api.example.com"}},
		{3, []string{"dev.api.example.com", "x.dev.api.example.com"}},
	} {
		cfg := Config{
			Domain: "example.com", Entries: []string{"dev.api", "x"},
			Concurrency: 2, Timeout: time.Second, Attempts: 1, Types: []string{"A"},
			Recursive: true, Depth: tc.depth,
			Resolver: dns.NewResolver(time.Second, addr), DNSServer: addr,
		}
		want, _ := runCollect(t, cfg, 0)
		if len(want) != tc.depth {
			t.Fatalf("depth %d: uninterrupted run found %v", tc.depth, want)
		}
		// Interrupted after the whole wordlist, with the parents found.
		cfg.ResumeFrom = len(cfg.Entries)
		cfg.ResumeParents = tc.parents
		rest, _ := runCollect(t, cfg, 0)
		for _, p := range tc.parents {
			rest[p] = true
		}
		if !maps.Equal(rest, want) {
			t.Errorf("depth %d: resumed run and its parents give %v, uninterrupted %v", tc.depth, rest, want)
		}
	}
}

// TestResumeSkipsWildcardParent covers #296: a parent found before the
// interrupt goes through the same wildcard check on resume as a parent found
// by a live run, so a wildcard subzone is skipped with a notice both times
// and the two runs report the same names.
func TestResumeSkipsWildcardParent(t *testing.T) {
	addr, stop := startUDPDNS(t, func(name string, _ uint16) ([4]byte, bool) {
		switch {
		case name == "dev.example.com":
			return [4]byte{192, 0, 2, 5}, true
		case strings.HasSuffix(name, ".dev.example.com"):
			return [4]byte{192, 0, 2, 99}, true
		default:
			return [4]byte{}, false
		}
	})
	defer stop()

	// run returns the names found and how many skip notices named dev.
	run := func(cfg Config) (map[string]bool, int) {
		events := make(chan Event, 64)
		go Run(context.Background(), cfg, events)
		found, skips := map[string]bool{}, 0
		for ev := range events {
			switch ev.Kind {
			case EventResult:
				found[ev.Result.Subdomain] = true
			case EventNotice:
				if ev.Notice == NoticeSkip && strings.Contains(ev.Message, "dev.example.com") {
					skips++
				}
			case EventError:
				t.Fatalf("unexpected error: %s", ev.Message)
			}
		}
		return found, skips
	}

	cfg := Config{
		Domain: "example.com", Entries: []string{"dev", "www", "api"},
		Concurrency: 2, Timeout: time.Second, Attempts: 1, Types: []string{"A"},
		Recursive: true, Depth: 2,
		Resolver: dns.NewResolver(time.Second, addr), DNSServer: addr,
	}
	want := map[string]bool{"dev.example.com": true}
	fresh, skips := run(cfg)
	if !maps.Equal(fresh, want) || skips != 1 {
		t.Fatalf("uninterrupted run: found %v with %d skip notices, want %v with 1", fresh, skips, want)
	}

	// Interrupted after the whole wordlist, with dev already found.
	cfg.ResumeFrom = len(cfg.Entries)
	cfg.ResumeParents = []string{"dev.example.com"}
	rest, skips := run(cfg)
	if len(rest) != 0 || skips != 1 {
		t.Fatalf("resumed run: found %v with %d skip notices, want nothing new with 1", rest, skips)
	}
}
