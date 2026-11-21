package subenum

import (
	"context"
	"fmt"
	"time"

	"github.com/TMHSDigital/subenum/internal/axfr"
	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/validate"
)

// ZoneOptions configures ProbeZone and ZoneTransfer.
type ZoneOptions struct {
	// Resolver finds the domain's name servers and their addresses, in the
	// forms Config.Resolver accepts. Empty means DefaultResolver. The
	// transfers themselves go to the name servers.
	Resolver string

	// Timeout bounds one lookup and the DNSSEC probe. A transfer is given
	// at least 10 seconds. Zero means DefaultTimeout.
	Timeout time.Duration

	// WalkNSEC makes ProbeZone also walk a zone the probe finds signed
	// with plain NSEC, as the CLI's -nsec-walk does, and list its names in
	// ZoneInfo.Walked (#437). The walk asks the name server that answered
	// the probe, one query per name.
	WalkNSEC bool

	// Rate paces the NSEC walk's queries, per second. Zero sends them
	// unpaced.
	Rate int

	// MaxQueries caps the NSEC walk's queries. Zero means the built-in cap
	// of 10,000.
	MaxQueries int
}

// ZoneInfo is what ProbeZone learned about a domain's zone.
type ZoneInfo struct {
	// Names are the names the transfers gave, relative to the domain
	// ("api", "dev.api"), sorted. They have not been resolved.
	Names []string

	// TransferAllowed lists the name servers that allowed a zone transfer.
	// Anyone can list such a zone; transfers should be limited to the
	// zone's secondaries.
	TransferAllowed []string

	// Denial is how the zone proves a name does not exist: "nsec" (plain
	// NSEC, so anyone can list every name by walking the zone), "nsec3",
	// "none" (no DNSSEC), or "" when no name server answered the probe.
	Denial string

	// Walked are the names the NSEC walk listed, relative to the domain,
	// sorted, with ZoneOptions.WalkNSEC. They have not been resolved.
	Walked []string

	// WalkStop says why the NSEC walk stopped before it listed the whole
	// zone (a loop in the chain, MaxQueries, a failed query), or why it did
	// not run (an NSEC3 or unsigned zone); "" when it listed every name or
	// was not asked for.
	WalkStop string
}

// ProbeZone does what the CLI's -axfr does before a scan: it looks up
// domain's name servers through opts.Resolver and asks each for a full zone
// transfer (AXFR), and one of them how the zone proves a name does not
// exist. Like the CLI, it asks at most 8 name servers and 2 addresses of
// each. Most servers refuse transfers, which is the correct configuration
// and not an error. The queries go to the domain's own name servers and are
// not paced; it sends about four per name server.
//
// The error reports an invalid domain or option, a name server lookup that
// failed, or a cancelled ctx.
func ProbeZone(ctx context.Context, domain string, opts ZoneOptions) (ZoneInfo, error) {
	return probeZone(ctx, domain, opts, nil, false)
}

// probeZone is ProbeZone that neither resolves nor contacts the name servers
// skip reports (#372), nor returns or asks about names it reports in an NSEC
// walk; nil skips none. noTransfer skips the transfers, for NSECWalk.
func probeZone(ctx context.Context, domain string, opts ZoneOptions, skip func(string) bool, noTransfer bool) (ZoneInfo, error) {
	domain, _, err := validate.NormalizeDomain(domain)
	if err != nil {
		return ZoneInfo{}, fmt.Errorf("subenum: domain: %w", err)
	}
	if opts.Timeout < 0 {
		return ZoneInfo{}, fmt.Errorf("subenum: Timeout must not be negative, got %s", opts.Timeout)
	}
	if opts.Rate < 0 || opts.MaxQueries < 0 {
		return ZoneInfo{}, fmt.Errorf("subenum: Rate and MaxQueries must not be negative, got %d and %d", opts.Rate, opts.MaxQueries)
	}
	resolver := orDefaultString(opts.Resolver, DefaultResolver)
	if normalized, err := validate.NormalizeDNSServer(resolver); err == nil {
		resolver = normalized
	}
	if err := validate.DNSServer(resolver); err != nil {
		return ZoneInfo{}, fmt.Errorf("subenum: Resolver %s: %w", dns.DisplayServer(resolver), err)
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	o := axfr.Options{Resolver: resolver, Port: zonePort, Timeout: timeout, Skip: skip, NoTransfer: noTransfer}
	if opts.WalkNSEC {
		o.Walk = &dns.WalkOptions{Timeout: timeout, MaxQueries: opts.MaxQueries, Limiter: dns.NewRateLimiter(opts.Rate), Skip: skip}
	}
	r := axfr.Try(ctx, domain, o)
	info := ZoneInfo{Names: r.Names, TransferAllowed: r.Allowed, Denial: string(r.Denial), Walked: r.Walked, WalkStop: r.WalkStop}
	if err := ctx.Err(); err != nil {
		return info, err
	}
	if r.Err != "" {
		return info, fmt.Errorf("subenum: zone transfer of %s: %s", domain, r.Err)
	}
	return info, nil
}

// zonePort is the port transfers go to; tests point it at a local server.
var zonePort = "53"

// ZoneTransfer returns the source behind the CLI's -axfr: the names a full
// zone transfer gives, from ProbeZone. Unlike the passive sources it queries
// the domain's own name servers, and those queries are not paced by
// Config.Rate. A domain whose name servers all refuse gives no names and no
// error.
func ZoneTransfer(opts ZoneOptions) Source {
	return zoneSource(opts)
}

type zoneSource ZoneOptions

// Name labels the source in Result.Sources as the CLI does (#273).
func (zoneSource) Name() string { return candidates.AXFR }

func (z zoneSource) Names(ctx context.Context, domain string) ([]string, error) {
	return z.names(ctx, domain, nil)
}

// names is Names skipping the name servers skip rules out of scope: a scan
// passes its Exclude test (#372).
func (z zoneSource) names(ctx context.Context, domain string, skip func(string) bool) ([]string, error) {
	info, err := probeZone(ctx, domain, ZoneOptions(z), skip, false)
	if err != nil {
		return nil, err
	}
	return info.Names, nil
}

// NSECWalk returns the source behind the CLI's -nsec-walk (#437): the names
// an NSEC walk lists when the domain's zone is signed with plain NSEC, from
// ProbeZone with WalkNSEC set but no transfer. The walk asks the domain's own
// name server, paced by opts.Rate (not Config.Rate) and capped by
// opts.MaxQueries; Config.Exclude applies to it. An NSEC3 or unsigned zone
// gives no names and no error.
func NSECWalk(opts ZoneOptions) Source {
	return walkSource(opts)
}

type walkSource ZoneOptions

// Name labels the source in Result.Sources as the CLI does.
func (walkSource) Name() string { return candidates.NSEC }

func (w walkSource) Names(ctx context.Context, domain string) ([]string, error) {
	return w.names(ctx, domain, nil)
}

// names is Names leaving out what skip rules out of scope: a scan passes
// its Exclude test.
func (w walkSource) names(ctx context.Context, domain string, skip func(string) bool) ([]string, error) {
	opts := ZoneOptions(w)
	opts.WalkNSEC = true
	info, err := probeZone(ctx, domain, opts, skip, true)
	if err != nil {
		return nil, err
	}
	return info.Walked, nil
}
