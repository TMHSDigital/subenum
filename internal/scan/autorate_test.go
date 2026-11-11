package scan

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// feed sends n lookups to a, failed ones first, and returns the notices.
func feed(a *autoRate, n, failed int) []string {
	var notices []string
	for i := range n {
		if msg := a.observe(i < failed); msg != "" {
			notices = append(notices, msg)
		}
	}
	return notices
}

// TestAutoRateBacksOffAndRecovers covers #220's controller: a bad window
// halves the rate, a healthy one raises it by a quarter up to where it
// started, and a window at the threshold changes nothing.
func TestAutoRateBacksOffAndRecovers(t *testing.T) {
	l := dns.NewAdjustableRateLimiter(100)
	a := newAutoRate(l, func() int64 { return 0 })
	if n := feed(a, autoRateWindow, autoRateWindow*reliabilityFailPercent/100); len(n) != 0 || l.Rate() != 100 {
		t.Fatalf("a window at the threshold changed the rate to %d: %v", l.Rate(), n)
	}

	a = newAutoRate(l, func() int64 { return 0 })
	n := feed(a, autoRateWindow, autoRateWindow)
	if l.Rate() != 50 || len(n) != 1 || !strings.Contains(n[0], "slowing down to 50") {
		t.Fatalf("after a bad window: rate %d, notices %v; want 50 and one notice", l.Rate(), n)
	}
	for _, want := range []int{62, 77, 96, 100, 100} {
		feed(a, autoRateWindow, 0)
		if l.Rate() != want {
			t.Fatalf("healthy window: rate %d, want %d", l.Rate(), want)
		}
	}
	if b, r := a.result(); b != 1 || r != 100 {
		t.Errorf("result = %d back-offs at %d, want 1 at 100", b, r)
	}
}

// TestAutoRateGivesUp: after halving down to the floor the controller stops,
// so the reliability guard can act.
func TestAutoRateGivesUp(t *testing.T) {
	l := dns.NewAdjustableRateLimiter(40)
	a := newAutoRate(l, func() int64 { return 0 })
	for _, want := range []int{20, 10, 5} {
		feed(a, autoRateWindow, autoRateWindow)
		if l.Rate() != want || a.gaveUp() {
			t.Fatalf("rate %d (gave up %v), want %d", l.Rate(), a.gaveUp(), want)
		}
	}
	feed(a, autoRateWindow, autoRateWindow)
	if !a.gaveUp() || l.Rate() != autoRateFloor {
		t.Errorf("at the floor: gave up %v, rate %d", a.gaveUp(), l.Rate())
	}
}

// TestAutoRateUnlimitedStart: with no -rate the first back-off halves the
// rate achieved so far.
func TestAutoRateUnlimitedStart(t *testing.T) {
	l := dns.NewAdjustableRateLimiter(0)
	a := newAutoRate(l, func() int64 { return 1 << 40 })
	a.start = time.Now().Add(-time.Second)
	feed(a, autoRateWindow, autoRateWindow)
	if r := l.Rate(); r <= autoRateFloor || r == 0 {
		t.Errorf("rate after the first back-off = %d, want half the achieved rate", r)
	}
}

// TestRunAutoRateKeepsGoing covers #220 end to end: a burst of timeouts that
// makes the reliability guard abort a plain scan only slows an AutoRate
// scan down, which then finishes with a notice and the back-offs counted.
func TestRunAutoRateKeepsGoing(t *testing.T) {
	const entries, failing = 600, 250
	run := func(auto bool) (*Event, []Event, int) {
		var n atomic.Int64
		cfg := Config{
			Domain: "example.com", Entries: makeEntries(entries), Concurrency: 4, Timeout: time.Second,
			Simulate: true, Attempts: 1, Rate: 1000, AutoRate: auto,
			resolveHook: func(context.Context, string) ([]dns.Record, dns.Outcome) {
				if n.Add(1) <= failing {
					return nil, dns.OutcomeTimeout
				}
				return nil, dns.OutcomeNXDomain
			},
		}
		events := make(chan Event, 64)
		go Run(context.Background(), cfg, events)
		var done *Event
		var errs []Event
		rate := 0
		for ev := range events {
			switch ev.Kind {
			case EventError:
				errs = append(errs, ev)
			case EventNotice:
				if ev.Notice == NoticeRate {
					rate++
				}
			case EventDone:
				e := ev
				done = &e
			}
		}
		if done == nil {
			t.Fatal("no EventDone")
		}
		return done, errs, rate
	}

	if done, errs, _ := run(false); len(errs) == 0 || !done.Stats.Aborted {
		t.Fatalf("control: want the reliability guard to abort, got errs %d aborted %v", len(errs), done.Stats.Aborted)
	}
	done, errs, notices := run(true)
	if len(errs) != 0 || done.Stats.Aborted {
		t.Fatalf("AutoRate scan aborted: %v", errs)
	}
	if done.Processed != entries || done.Stats.RateBackoffs < 1 || notices < 1 {
		t.Errorf("processed %d of %d, back-offs %d, rate notices %d", done.Processed, entries, done.Stats.RateBackoffs, notices)
	}
	if done.Stats.FinalRate <= 0 || done.Stats.FinalRate > 1000 {
		t.Errorf("FinalRate = %d, want within (0, 1000]", done.Stats.FinalRate)
	}
}
