package scan

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// Config holds all parameters needed to run a subdomain scan.
type Config struct {
	Domain      string
	Entries     []string
	Concurrency int
	Timeout     time.Duration
	DNSServer   string
	Simulate    bool
	HitRate     int
	Attempts    int
	Force       bool
	Verbose     bool
	Rate        int
}

// EventKind categorises a scan event.
type EventKind int

const (
	EventResult   EventKind = iota // a subdomain resolved
	EventProgress                  // progress update
	EventWildcard                  // wildcard DNS detected
	EventError                     // non-fatal error message
	EventDone                      // scan finished
)

// Event is emitted on the events channel during a scan.
type Event struct {
	Kind      EventKind
	Domain    string       // EventResult: the resolved subdomain
	Records   []dns.Record // EventResult: the resolved records
	Processed int64        // EventProgress
	Total     int64        // EventProgress
	Found     int64        // EventProgress / EventDone
	Message   string       // EventError / EventWildcard
}

// Run executes the subdomain scan, sending events to the provided channel.
// The caller must close or cancel ctx to abort early.
// Run closes events when the scan completes.
func Run(ctx context.Context, cfg Config, events chan<- Event) {
	defer close(events)

	total := int64(len(cfg.Entries))
	var processed, found int64

	// Wildcard detection (skip in simulation mode).
	if !cfg.Simulate {
		isWildcard, err := dns.CheckWildcard(ctx, cfg.Domain, cfg.Timeout, cfg.DNSServer)
		if err != nil {
			events <- Event{Kind: EventError, Message: "wildcard detection failed: " + err.Error()}
			return
		}
		if isWildcard {
			msg := "WARNING: Wildcard DNS detected — all subdomains resolve for " + cfg.Domain
			events <- Event{Kind: EventWildcard, Message: msg}
			if !cfg.Force {
				events <- Event{Kind: EventError, Message: "Results would be meaningless. Use -force to scan anyway."}
				return
			}
		}
	}

	subdomains := make(chan string)
	var wg sync.WaitGroup

	// Optional rate limiter: a shared ticker gate paces total queries per second
	// across the whole worker pool. nil means unlimited.
	var limiter <-chan time.Time
	if cfg.Rate > 0 {
		interval := time.Second / time.Duration(cfg.Rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		rl := time.NewTicker(interval)
		defer rl.Stop()
		limiter = rl.C
	}

	// Progress ticker - fires every second.
	// tickerDone signals the goroutine to stop; tickerStopped confirms it has
	// fully exited so we never close events while a send is pending.
	tickerDone := make(chan struct{})
	tickerStopped := make(chan struct{})
	ticker := time.NewTicker(time.Second)
	go func() {
		defer close(tickerStopped)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p := atomic.LoadInt64(&processed)
				f := atomic.LoadInt64(&found)
				select {
				case events <- Event{Kind: EventProgress, Processed: p, Total: total, Found: f}:
				case <-tickerDone:
					return
				case <-ctx.Done():
					return
				}
			case <-tickerDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Worker pool.
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for prefix := range subdomains {
				if ctx.Err() != nil {
					atomic.AddInt64(&processed, 1)
					continue
				}
				if limiter != nil {
					select {
					case <-limiter:
					case <-ctx.Done():
						atomic.AddInt64(&processed, 1)
						continue
					}
				}
				fullDomain := prefix + "." + cfg.Domain
				var resolved bool
				var records []dns.Record
				if cfg.Simulate {
					records, resolved = dns.SimulateResolve(fullDomain, cfg.HitRate, cfg.Verbose)
				} else {
					records, resolved = dns.ResolveDomainWithRetry(ctx, fullDomain, cfg.Timeout, cfg.DNSServer, cfg.Verbose, cfg.Attempts)
				}
				if resolved {
					atomic.AddInt64(&found, 1)
					events <- Event{Kind: EventResult, Domain: fullDomain, Records: records}
				}
				atomic.AddInt64(&processed, 1)
			}
		}()
	}

	// Feed entries into the worker pool.
	for _, entry := range cfg.Entries {
		select {
		case <-ctx.Done():
			goto drain
		case subdomains <- entry:
		}
	}

drain:
	close(subdomains)
	wg.Wait()
	// Stop the ticker goroutine and wait for it to fully exit before emitting
	// EventDone, so the deferred close(events) can never race an in-flight
	// ticker send.
	close(tickerDone)
	<-tickerStopped

	events <- Event{
		Kind:      EventDone,
		Processed: atomic.LoadInt64(&processed),
		Total:     total,
		Found:     atomic.LoadInt64(&found),
	}
}
