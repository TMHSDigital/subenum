package dns

import (
	"context"
	"sync"
	"time"
)

// RateLimiter spaces events at least 1/rate apart across all callers. It hands
// out reservations instead of draining a ticker, so a busy worker pool cannot
// lose ticks and fall below the configured rate. A nil *RateLimiter never
// waits.
type RateLimiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
	reserved int64 // slots handed out; read by tests
}

// NewRateLimiter returns a limiter for perSecond events, or nil (unlimited)
// when perSecond <= 0.
func NewRateLimiter(perSecond int) *RateLimiter {
	if perSecond <= 0 {
		return nil
	}
	interval := time.Second / time.Duration(perSecond)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	return &RateLimiter{interval: interval}
}

// NewAdjustableRateLimiter is NewRateLimiter whose result is never nil, so
// SetRate can slow it down later (#220). perSecond <= 0 starts unlimited.
func NewAdjustableRateLimiter(perSecond int) *RateLimiter {
	if l := NewRateLimiter(perSecond); l != nil {
		return l
	}
	return &RateLimiter{}
}

// SetRate changes the rate for slots reserved from now on; perSecond <= 0 is
// unlimited. Slots already handed out keep their time.
func (l *RateLimiter) SetRate(perSecond int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if perSecond <= 0 {
		l.interval = 0
		return
	}
	l.interval = max(time.Second/time.Duration(perSecond), time.Nanosecond)
}

// Rate returns the current rate in events per second, 0 when unlimited.
func (l *RateLimiter) Rate() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.interval <= 0 {
		return 0
	}
	return int(time.Second / l.interval)
}

// Wait blocks until the caller's reserved slot arrives or ctx is done.
func (l *RateLimiter) Wait(ctx context.Context) error {
	if l == nil {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	slot := l.next
	if slot.Before(now) {
		slot = now
	}
	l.next = slot.Add(l.interval)
	l.reserved++
	l.mu.Unlock()

	d := time.Until(slot)
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type limiterKey struct{}

// WithLimiter attaches l to ctx. Every lookup ResolveTypes performs under that
// ctx (scan jobs, retries, wildcard probes, the preflight) first takes one slot
// per DNS query it is about to send, before its own timeout starts, so waiting
// for the rate can never turn into a spurious timeout.
func WithLimiter(ctx context.Context, l *RateLimiter) context.Context {
	if l == nil {
		return ctx
	}
	return context.WithValue(ctx, limiterKey{}, l)
}

func limiterFrom(ctx context.Context) *RateLimiter {
	l, _ := ctx.Value(limiterKey{}).(*RateLimiter)
	return l
}
