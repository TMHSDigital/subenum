package cli

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/TMHSDigital/subenum/internal/axfr"
	"github.com/TMHSDigital/subenum/internal/dns"
)

// heldLines keeps Info lines to print later, so work that runs alongside
// other work prints in the order it would have run in (#365). It is safe
// for concurrent use.
type heldLines struct {
	mu    sync.Mutex
	lines []string
}

// Info holds one formatted line.
func (h *heldLines) Info(format string, a ...any) {
	h.mu.Lock()
	h.lines = append(h.lines, fmt.Sprintf(format, a...))
	h.mu.Unlock()
}

// replay prints the held lines through info, in order, and forgets them.
func (h *heldLines) replay(info func(string, ...any)) {
	h.mu.Lock()
	lines := h.lines
	h.lines = nil
	h.mu.Unlock()
	for _, line := range lines {
		info("%s", line)
	}
}

// targetAXFR is a target's zone transfer attempt (#85).
type targetAXFR struct {
	names   []string   // relative to the target, from every transfer that succeeded
	allowed []string   // name servers that allowed the transfer: a misconfiguration
	tried   int        // name server addresses asked
	denial  dns.Denial // how the zone proves a name does not exist; "" when no server answered the probe (#234)
	queries int64      // DNS queries sent: the NS and address lookups, the denial probe, and one per transfer
	done    bool       // the attempt ran (it may have found nothing)
	err     string     // why no transfer could be attempted, such as a failed NS lookup

	walked   []string // relative to the target, from an -nsec-walk (#437)
	walkStop string   // why the walk stopped early or did not run
}

// zoneTransfer tries a full zone transfer of target from each of its name
// servers, found through the trusted resolver, with the library's shared
// implementation (#314), and with -nsec-walk walks a plain-NSEC zone (#437);
// -nsec-walk alone skips the transfers. A resumed run reuses the names the
// interrupted run got, so its candidate list matches. Name servers skip
// rules out of scope are neither resolved nor contacted (#372), and the walk
// neither returns nor asks about names it rules out. deadline is when
// -max-duration runs out (zero for none).
func zoneTransfer(ctx context.Context, f cliFlags, port, target string, saved *resumeTarget, info func(string, ...any), skip func(string) bool, deadline time.Time) targetAXFR {
	if saved != nil && saved.AXFRDone {
		return targetAXFR{names: saved.AXFR, allowed: saved.AXFRServers, denial: dns.Denial(saved.Denial), done: true,
			walked: saved.NSEC, walkStop: saved.NSECStop}
	}
	if saved != nil && saved.Done {
		return targetAXFR{} // finished before the interrupt: not scanned again (#315)
	}
	opts := axfr.Options{
		Resolver: f.dnsServer,
		Port:     port,
		Timeout:  time.Duration(f.timeoutMs) * time.Millisecond,
		Info:     info,
		Skip:     skip,
		// -nsec-walk alone asks for no transfer.
		NoTransfer: !f.axfr,
	}
	if f.nsecWalk {
		// The walk's queries are paced by -rate and count against
		// -max-queries; it stops when -max-duration runs out.
		opts.Walk = &dns.WalkOptions{
			Timeout:    opts.Timeout,
			MaxQueries: f.maxQueries,
			Limiter:    dns.NewRateLimiter(f.rate),
			Deadline:   deadline,
			Skip:       skip,
		}
	}
	if f.verbose {
		opts.Debug = info
	}
	if f.simZone != "" {
		// Lab mode: the lab server answers for every name server, so the
		// transfer never leaves the machine (#434).
		opts.Server = f.dnsServer
	}
	r := axfr.Try(ctx, target, opts)
	res := targetAXFR{names: r.Names, allowed: r.Allowed, tried: r.Tried, denial: r.Denial, queries: r.Queries, done: true, err: r.Err,
		walked: r.Walked, walkStop: r.WalkStop}
	if r.Err != "" {
		switch {
		case !f.axfr:
			info("Warning: -nsec-walk: %s; scanning %s without an NSEC walk", r.Err, target)
		case f.nsecWalk:
			info("Warning: -axfr: %s; scanning %s without a zone transfer or an NSEC walk", r.Err, target)
		default:
			info("Warning: -axfr: %s; scanning %s without a zone transfer", r.Err, target)
		}
		return res
	}
	if f.axfr && len(r.Allowed) == 0 && f.verbose && ctx.Err() == nil {
		info("-axfr: no name server of %s allowed a zone transfer (%d addresses asked)", target, r.Tried)
	}
	return res
}
