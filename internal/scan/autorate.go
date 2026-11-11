package scan

import (
	"fmt"
	"sync"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// AutoRate tuning (#220).
const (
	// autoRateWindow is how many recent lookups the controller judges.
	autoRateWindow = 200
	// autoRateHealthyPercent is the failure rate at or below which the rate
	// is raised again after a back-off.
	autoRateHealthyPercent = 5
	// autoRateMaxBackoffs is how many times the rate is halved before the
	// reliability guard is allowed to act.
	autoRateMaxBackoffs = 6
	// autoRateFloor is the slowest rate a back-off goes to, in queries per
	// second.
	autoRateFloor = 5
)

// autoRate is the AutoRate controller (#220). It judges the last
// autoRateWindow lookups: when more than reliabilityFailPercent of them
// failed, it halves the limiter's rate (starting from the rate achieved so
// far when there was no limit) and starts a new window. When a full window
// is healthy again it raises the rate by a quarter, up to the rate it first
// backed off from. Once it has backed off autoRateMaxBackoffs times, or is
// at autoRateFloor, it gives up and the reliability guard applies as usual.
type autoRate struct {
	mu      sync.Mutex
	limiter *dns.RateLimiter
	start   time.Time
	sent    func() int64 // DNS queries sent so far, to measure the rate achieved

	window    [autoRateWindow]bool // true = failed
	n, next   int
	fails     int
	backoffs  int
	top       int // the rate before the first back-off
	exhausted bool
}

func newAutoRate(l *dns.RateLimiter, sent func() int64) *autoRate {
	return &autoRate{limiter: l, start: time.Now(), sent: sent}
}

// observe records one lookup and returns a notice when it changed the rate.
func (a *autoRate) observe(failed bool) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.n == autoRateWindow && a.window[a.next] {
		a.fails--
	}
	a.window[a.next] = failed
	if failed {
		a.fails++
	}
	a.next = (a.next + 1) % autoRateWindow
	a.n = min(a.n+1, autoRateWindow)
	if a.n < autoRateWindow || a.exhausted {
		return ""
	}

	cur := a.limiter.Rate()
	switch {
	case a.fails*100 > autoRateWindow*reliabilityFailPercent:
		if cur == 0 {
			cur = a.achieved()
		}
		if a.backoffs >= autoRateMaxBackoffs || cur <= autoRateFloor {
			a.exhausted = true
			return ""
		}
		if a.top == 0 {
			a.top = cur
		}
		next := max(cur/2, autoRateFloor)
		pct := a.fails * 100 / autoRateWindow
		a.limiter.SetRate(next)
		a.backoffs++
		a.reset()
		return fmt.Sprintf("%d%% of the last %d lookups failed; slowing down to %d queries per second ({rate} %d)", pct, autoRateWindow, next, next)
	case a.backoffs > 0 && cur < a.top && a.fails*100 <= autoRateWindow*autoRateHealthyPercent:
		next := min(a.top, cur+max(cur/4, 1))
		a.limiter.SetRate(next)
		a.reset()
		return fmt.Sprintf("lookups are succeeding again; speeding up to %d queries per second", next)
	}
	return ""
}

// achieved is the query rate the scan has reached so far, at least twice
// the floor so a first back-off always slows down.
func (a *autoRate) achieved() int {
	secs := time.Since(a.start).Seconds()
	if secs <= 0 {
		return 2 * autoRateFloor
	}
	return max(int(float64(a.sent())/secs), 2*autoRateFloor)
}

func (a *autoRate) reset() {
	a.window = [autoRateWindow]bool{}
	a.n, a.next, a.fails = 0, 0, 0
}

// gaveUp reports whether the controller has stopped backing off.
func (a *autoRate) gaveUp() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.exhausted
}

// result returns the number of back-offs and the final rate.
func (a *autoRate) result() (backoffs int64, rate int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return int64(a.backoffs), int64(a.limiter.Rate())
}
