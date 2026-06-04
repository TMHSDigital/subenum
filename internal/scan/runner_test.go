package scan

import (
	"context"
	"testing"
	"time"
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
