package scan

import (
	"context"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// The inconclusive names are collected only for a reader (#300).

// TestInconclusiveListOnlyWhenAsked: without ListInconclusive the names are
// not listed, with or without the retry pass, and every count is what it is
// with the list.
func TestInconclusiveListOnlyWhenAsked(t *testing.T) {
	entries := []string{"ok1", "gone1", "flaky-ok1", "flaky-ok2", "flaky-gone1", "flaky-down1", "flaky-down2"}
	run := func(retry, list bool) Stats {
		cfg := Config{
			Domain: "example.com", Entries: entries, Concurrency: 3, Timeout: time.Second,
			Simulate: true, Attempts: 1, RetryInconclusive: retry, ListInconclusive: list,
			resolveHook: retryHook(&sync.Map{}),
		}
		events := make(chan Event, 64)
		go Run(context.Background(), cfg, events)
		done, errs, _ := collect(events)
		if len(errs) != 0 || done == nil {
			t.Fatalf("retry %v list %v: errors %v, done %v", retry, list, errs, done)
		}
		return done.Stats
	}
	for _, retry := range []bool{false, true} {
		with, without := run(retry, true), run(retry, false)
		if without.Inconclusive != nil {
			t.Errorf("retry %v: Inconclusive = %v without ListInconclusive, want nil", retry, without.Inconclusive)
		}
		if int64(len(with.Inconclusive)) != with.Timeout {
			t.Errorf("retry %v: Inconclusive lists %d names, want the %d timeouts", retry, len(with.Inconclusive), with.Timeout)
		}
		with.Inconclusive = nil
		if without.Sum() != int64(len(entries)) || without.Found != with.Found || without.NXDomain != with.NXDomain ||
			without.Timeout != with.Timeout || without.Retried != with.Retried || without.Recovered != with.Recovered {
			t.Errorf("retry %v: counts without the list %+v, with it %+v; want the same", retry, without, with)
		}
	}
}

// TestInconclusiveListNamesRecursiveChildren: the list rebuilds a wordlist
// entry's name from its index and keeps a recursive child's name as it was.
func TestInconclusiveListNamesRecursiveChildren(t *testing.T) {
	cfg := Config{
		Domain: "example.com", Entries: []string{"ok", "down"}, Concurrency: 2, Timeout: time.Second,
		Simulate: true, Attempts: 1, Recursive: true, Depth: 2, ListInconclusive: true,
		resolveHook: func(_ context.Context, name string) ([]dns.Record, dns.Outcome) {
			if name == "ok.example.com" {
				return []dns.Record{{Type: "A", Value: "192.0.2.1"}}, dns.OutcomeFound
			}
			return nil, dns.OutcomeTimeout
		},
	}
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	done, errs, _ := collect(events)
	if len(errs) != 0 || done == nil {
		t.Fatalf("errors %v, done %v", errs, done)
	}
	want := []string{"down.example.com", "down.ok.example.com", "ok.ok.example.com"}
	if !slices.Equal(done.Stats.Inconclusive, want) {
		t.Errorf("Inconclusive = %v, want %v", done.Stats.Inconclusive, want)
	}
}

// TestFailedLookupsAreNotRetainedWithoutTheList: with no reader for the
// names, a scan whose every lookup is refused holds no more memory at its
// last lookup than one whose every lookup is answered.
func TestFailedLookupsAreNotRetainedWithoutTheList(t *testing.T) {
	const n = 100_000
	entries := make([]string, n)
	for i := range entries {
		entries[i] = "host-" + itoa(i)
	}
	last := entries[n-1] + ".example.com"
	heapAtEnd := func(o dns.Outcome) uint64 {
		var heap uint64
		cfg := Config{
			Domain: "example.com", Entries: entries, Concurrency: 1, Timeout: time.Second,
			Simulate: true, Attempts: 1, NoAbort: true,
			resolveHook: func(_ context.Context, name string) ([]dns.Record, dns.Outcome) {
				if name == last {
					var m runtime.MemStats
					runtime.GC()
					runtime.ReadMemStats(&m)
					heap = m.HeapAlloc
				}
				return nil, o
			},
		}
		events := make(chan Event, 64)
		go Run(context.Background(), cfg, events)
		done, _, _ := collect(events)
		if done == nil || done.Stats.Sum() != n {
			t.Fatalf("outcome %v: done %+v, want %d lookups", o, done, n)
		}
		if heap == 0 {
			t.Fatalf("outcome %v: the last name was never looked up", o)
		}
		return heap
	}
	answered, refused := heapAtEnd(dns.OutcomeNXDomain), heapAtEnd(dns.OutcomeRefused)
	// A retained entry costs at least 32 bytes, 3.2 MB here; allow 1 MB of noise.
	if refused > answered+1<<20 {
		t.Errorf("heap at the last lookup: %d bytes with every lookup refused, %d with every lookup answered; failed lookups are retained",
			refused, answered)
	}
}
