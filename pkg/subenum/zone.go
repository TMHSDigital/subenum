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
	return probeZone(ctx, domain, opts, nil)
}

// probeZone is ProbeZone that neither resolves nor contacts the name servers
// skip reports (#372); nil skips none.
func probeZone(ctx context.Context, domain string, opts ZoneOptions, skip func(string) bool) (ZoneInfo, error) {
	domain, _, err := validate.NormalizeDomain(domain)
	if err != nil {
		return ZoneInfo{}, fmt.Errorf("subenum: domain: %w", err)
	}
	if opts.Timeout < 0 {
		return ZoneInfo{}, fmt.Errorf("subenum: Timeout must not be negative, got %s", opts.Timeout)
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
	r := axfr.Try(ctx, domain, axfr.Options{Resolver: resolver, Port: zonePort, Timeout: timeout, Skip: skip})
	info := ZoneInfo{Names: r.Names, TransferAllowed: r.Allowed, Denial: string(r.Denial)}
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
	info, err := probeZone(ctx, domain, ZoneOptions(z), skip)
	if err != nil {
		return nil, err
	}
	return info.Names, nil
}
