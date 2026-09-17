package scan

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// makeEntries builds a synthetic wordlist of n prefixes.
func makeEntries(n int) []string {
	entries := make([]string, n)
	for i := range entries {
		entries[i] = "p" + itoa(i)
	}
	return entries
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// TestRunSimulateConcurrent runs a simulate-mode scan with concurrency > 1 and
// asserts an EventDone arrives with Processed == Total. Under -race this also
// exercises the rand fix (simulate) and the ticker shutdown fix.
func TestRunSimulateConcurrent(t *testing.T) {
	total := int64(2000)
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(int(total)),
		Concurrency: 16,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     50,
		Attempts:    1,
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)

	var done *Event
	for ev := range events {
		if ev.Kind == EventDone {
			e := ev
			done = &e
		}
	}

	if done == nil {
		t.Fatal("no EventDone received")
	}
	if done.Total != total {
		t.Errorf("EventDone.Total = %d, want %d", done.Total, total)
	}
	if done.Processed != total {
		t.Errorf("EventDone.Processed = %d, want %d", done.Processed, total)
	}
}

// TestRunRecursiveEnqueuesChildren exercises the restructured queue lifecycle:
// resolved subdomains enqueue depth-capped children mid-scan. It asserts no
// panic (send on closed channel), clean completion, and that recursion expands
// the total beyond the initial entry count. Run under -race.
func TestRunRecursiveEnqueuesChildren(t *testing.T) {
	// hitRate 100 so every job resolves and spawns children, maximizing the
	// chance of catching a send-on-closed-channel race.
	cfg := Config{
		Domain:      "example.com",
		Entries:     []string{"www", "api", "dev"},
		Concurrency: 8,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     100,
		Attempts:    1,
		Recursive:   true,
		Depth:       3,
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)

	var done *Event
	results := 0
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			results++
		case EventDone:
			e := ev
			done = &e
		}
	}

	if done == nil {
		t.Fatal("no EventDone received")
	}
	// Initial 3 entries, each resolving and spawning 3 children to depth 3:
	// 3 + 3*3 + 3*3*3 = 39 unique jobs.
	if done.Total <= 3 {
		t.Errorf("expected recursion to expand total beyond initial 3, got %d", done.Total)
	}
	if done.Processed != done.Total {
		t.Errorf("Processed %d != Total %d", done.Processed, done.Total)
	}
	if int64(results) != done.Found {
		t.Errorf("result events %d != Found %d", results, done.Found)
	}
}

// TestRunRecursiveLoopProtection asserts the visited set prevents duplicate or
// cyclic work: with depth high and full resolution, the job count stays finite
// and equals the unique domain count.
func TestRunRecursiveLoopProtection(t *testing.T) {
	cfg := Config{
		Domain:      "example.com",
		Entries:     []string{"a", "b"},
		Concurrency: 4,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     100,
		Attempts:    1,
		Recursive:   true,
		Depth:       4,
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)

	var done *Event
	for ev := range events {
		if ev.Kind == EventDone {
			e := ev
			done = &e
		}
	}
	if done == nil {
		t.Fatal("no EventDone received")
	}
	// 2 entries to depth 4: 2 + 4 + 8 + 16 = 30 unique jobs.
	if done.Total != 30 {
		t.Errorf("expected 30 unique jobs, got %d", done.Total)
	}
	if done.Processed != done.Total {
		t.Errorf("Processed %d != Total %d", done.Processed, done.Total)
	}
}

// TestRunRateLimit asserts that -rate paces queries: N queries at R qps should
// take at least (N-1)/R seconds. Uses simulate mode so it is network-free.
func TestRunRateLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive rate limit test in short mode")
	}

	const queries = 20
	const rate = 10 // qps
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(queries),
		Concurrency: 8,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     50,
		Attempts:    1,
		Rate:        rate,
	}

	events := make(chan Event, 64)
	start := time.Now()
	go Run(context.Background(), cfg, events)
	for range events { //nolint:revive // draining
	}
	elapsed := time.Since(start)

	// Floor: the first tick fires after one interval, so expect at least
	// (queries-1)/rate seconds, with a margin for scheduling jitter.
	minExpected := time.Duration(float64(queries-1) / float64(rate) * 0.8 * float64(time.Second))
	if elapsed < minExpected {
		t.Errorf("rate-limited scan finished too fast: %s < %s", elapsed, minExpected)
	}
}

// TestRunContextCancel cancels mid-scan and asserts Run returns and closes the
// events channel promptly.
func TestRunContextCancel(t *testing.T) {
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(100000),
		Concurrency: 8,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     50,
		Attempts:    1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan Event, 64)
	go Run(ctx, cfg, events)

	// Consume a few events, then cancel.
	received := 0
	for ev := range events {
		received++
		if received == 1 || ev.Kind == EventProgress {
			cancel()
		}
		if received > 20 {
			cancel()
		}
	}

	// Reaching here means the channel was closed (Run returned) after cancel.
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("events channel still open after Run returned")
		}
	default:
	}
}

func collect(events <-chan Event) (done *Event, errs []Event, results int) {
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			results++
		case EventError:
			errs = append(errs, ev)
		case EventDone:
			e := ev
			done = &e
		}
	}
	return done, errs, results
}

func hookOutcome(o dns.Outcome) func(context.Context, string) ([]dns.Record, dns.Outcome) {
	return func(context.Context, string) ([]dns.Record, dns.Outcome) {
		if o == dns.OutcomeFound {
			return []dns.Record{{Type: "A", Value: "192.0.2.1"}}, o
		}
		return nil, o
	}
}

// TestRunStatsSumToProcessed injects a mix of classified outcomes in simulate
// mode and asserts every processed job is accounted for. Failure rate stays
// under the reliability threshold so the scan completes.
func TestRunStatsSumToProcessed(t *testing.T) {
	var n atomic.Int64
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(250),
		Concurrency: 8,
		Timeout:     time.Second,
		Simulate:    true,
		Attempts:    1,
		resolveHook: func(context.Context, string) ([]dns.Record, dns.Outcome) {
			switch n.Add(1) % 10 {
			case 0:
				return []dns.Record{{Type: "A", Value: "192.0.2.1"}}, dns.OutcomeFound
			case 1:
				return nil, dns.OutcomeTimeout
			default:
				return nil, dns.OutcomeNXDomain
			}
		},
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	done, errs, results := collect(events)

	if done == nil {
		t.Fatal("no EventDone received")
	}
	if len(errs) != 0 {
		t.Fatalf("reliability guard fired unexpectedly: %q", errs[0].Message)
	}
	if done.Processed != done.Total {
		t.Errorf("Processed %d != Total %d", done.Processed, done.Total)
	}
	if done.Stats.Sum() != done.Processed {
		t.Errorf("stats sum %d != processed %d: %+v", done.Stats.Sum(), done.Processed, done.Stats)
	}
	if done.Found != done.Stats.Found {
		t.Errorf("Found %d != Stats.Found %d", done.Found, done.Stats.Found)
	}
	if int64(results) != done.Found {
		t.Errorf("result events %d != Found %d", results, done.Found)
	}
	if done.Stats.Timeout == 0 {
		t.Error("expected some timeout outcomes from the hook")
	}
	if done.Stats.NXDomain == 0 {
		t.Error("expected some nxdomain outcomes from the hook")
	}
}

// TestRunReliabilityGuardAborts injects a high timeout rate and asserts the
// guard emits EventError, names the failure rate, and cancels the scan.
func TestRunReliabilityGuardAborts(t *testing.T) {
	n := reliabilityMinJobs + 50
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(n),
		Concurrency: 4,
		Timeout:     time.Second,
		Simulate:    true,
		Attempts:    1,
		Rate:        0,
		resolveHook: hookOutcome(dns.OutcomeTimeout),
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	done, errs, _ := collect(events)

	if len(errs) == 0 {
		t.Fatal("expected EventError from reliability guard")
	}
	msg := errs[0].Message
	if !strings.Contains(msg, "aborting scan") {
		t.Errorf("error message %q: want aborting scan", msg)
	}
	if !strings.Contains(msg, "timeout/refused/other") {
		t.Errorf("error message %q: want failure classes", msg)
	}
	if !strings.Contains(msg, "-t 4") || !strings.Contains(msg, "-rate 0") {
		t.Errorf("error message %q: want configured -t and -rate", msg)
	}
	if done == nil {
		t.Fatal("no EventDone received after abort")
	}
	if done.Stats.Sum() != done.Processed {
		t.Errorf("stats sum %d != processed %d: %+v", done.Stats.Sum(), done.Processed, done.Stats)
	}
	if done.Stats.Timeout == 0 {
		t.Error("expected timeout counter to be populated")
	}
}

// TestRunReliabilityGuardNoAbort keeps scanning after the warning.
func TestRunReliabilityGuardNoAbort(t *testing.T) {
	n := reliabilityMinJobs + 50
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(n),
		Concurrency: 8,
		Timeout:     time.Second,
		Simulate:    true,
		Attempts:    1,
		NoAbort:     true,
		resolveHook: hookOutcome(dns.OutcomeRefused),
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	done, errs, _ := collect(events)

	if len(errs) == 0 {
		t.Fatal("expected warning EventError from reliability guard")
	}
	if !strings.Contains(errs[0].Message, "warning") {
		t.Errorf("error message %q: want warning", errs[0].Message)
	}
	if done == nil {
		t.Fatal("no EventDone received")
	}
	if done.Processed != int64(n) {
		t.Errorf("NoAbort should finish all %d jobs, processed %d", n, done.Processed)
	}
	if done.Stats.Sum() != done.Processed {
		t.Errorf("stats sum %d != processed %d: %+v", done.Stats.Sum(), done.Processed, done.Stats)
	}
	if done.Stats.Refused != int64(n) {
		t.Errorf("Refused = %d, want %d", done.Stats.Refused, n)
	}
}
