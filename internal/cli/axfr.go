package cli

import (
	"context"
	"time"

	"github.com/TMHSDigital/subenum/internal/axfr"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
)

// targetAXFR is a target's zone transfer attempt (#85).
type targetAXFR struct {
	names   []string   // relative to the target, from every transfer that succeeded
	allowed []string   // name servers that allowed the transfer: a misconfiguration
	tried   int        // name server addresses asked
	denial  dns.Denial // how the zone proves a name does not exist; "" when no server answered the probe (#234)
	queries int64      // DNS queries sent: the NS and address lookups, the denial probe, and one per transfer
	done    bool       // the attempt ran (it may have found nothing)
	err     string     // why no transfer could be attempted, such as a failed NS lookup
}

// zoneTransfer tries a full zone transfer of target from each of its name
// servers, found through the trusted resolver, with the library's shared
// implementation (#314). A resumed run reuses the names the interrupted run
// got, so its candidate list matches.
func zoneTransfer(ctx context.Context, f cliFlags, port, target string, saved *resumeTarget, out *output.Writer) targetAXFR {
	if saved != nil && saved.AXFRDone {
		return targetAXFR{names: saved.AXFR, allowed: saved.AXFRServers, denial: dns.Denial(saved.Denial), done: true}
	}
	opts := axfr.Options{
		Resolver: f.dnsServer,
		Port:     port,
		Timeout:  time.Duration(f.timeoutMs) * time.Millisecond,
		Info:     out.Info,
	}
	if f.verbose {
		opts.Debug = out.Info
	}
	r := axfr.Try(ctx, target, opts)
	res := targetAXFR{names: r.Names, allowed: r.Allowed, tried: r.Tried, denial: r.Denial, queries: r.Queries, done: true, err: r.Err}
	if r.Err != "" {
		out.Info("Warning: -axfr: %s; scanning %s without a zone transfer", r.Err, target)
		return res
	}
	if len(r.Allowed) == 0 && f.verbose && ctx.Err() == nil {
		out.Info("-axfr: no name server of %s allowed a zone transfer (%d addresses asked)", target, r.Tried)
	}
	return res
}
