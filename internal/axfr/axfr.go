// Package axfr tries a full zone transfer of a domain from each of its name
// servers, and probes how the zone proves a name does not exist. The CLI's
// -axfr and the library's ZoneTransfer and ProbeZone both run it (#314).
package axfr

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// Bounds (#85): a target with many name servers, or name servers with many
// addresses, cannot turn an attempt into a flood.
const (
	MaxServers     = 8
	MinTimeout     = 10 * time.Second
	AddrsPerServer = 2
)

// Options configures one attempt.
type Options struct {
	// Resolver finds the name servers and their addresses, in any form
	// dns.NewResolver accepts.
	Resolver string
	// Port is the port transfers and the denial probe go to; "" is 53.
	Port string
	// Timeout bounds one lookup and the denial probe; a transfer gets at
	// least MinTimeout.
	Timeout time.Duration
	// Info receives findings and unexpected failures; Debug receives detail
	// worth showing only on request. Nil discards them.
	Info, Debug func(format string, args ...any)
}

// Result is what an attempt found.
type Result struct {
	Names   []string   // relative to the target, from every transfer that succeeded, sorted
	Allowed []string   // name servers that allowed the transfer: a misconfiguration
	Tried   int        // name server addresses asked
	Denial  dns.Denial // how the zone proves a name does not exist; "" when no server answered the probe (#234)
	Queries int64      // DNS queries sent: the NS and address lookups, the denial probe, and one per transfer
	Err     string     // why no transfer could be attempted, such as a failed NS lookup
}

func logf(f func(string, ...any), format string, args ...any) {
	if f != nil {
		f(format, args...)
	}
}

// probeDenial asks one authoritative address how target proves a name does
// not exist (#234). Plain NSEC means anyone can list the zone by walking it,
// which is reported like an allowed transfer. A failed probe is "" so the
// next address is tried.
func probeDenial(ctx context.Context, o Options, host, addr, target string) dns.Denial {
	d, err := dns.ProbeDenial(ctx, net.JoinHostPort(addr, o.Port), target, o.Timeout)
	if err != nil {
		logf(o.Debug, "-axfr: DNSSEC denial probe to %s (%s): %v", host, addr, err)
		return ""
	}
	if d == dns.DenialNSEC {
		logf(o.Info, "Zone walkable: %s signs %s with plain NSEC, so anyone can list every name by walking it. NSEC3 would hide them.", host, target)
	} else {
		logf(o.Debug, "-axfr: %s proves absent names with %s; the zone cannot be walked", target, d)
	}
	return d
}

// Try tries a full zone transfer (AXFR) of target from each of its name
// servers, found through o.Resolver. A server that allows it gives every
// name in the zone in one query; most refuse, which is the correct
// configuration and not reported as an error.
func Try(ctx context.Context, target string, o Options) Result {
	if o.Port == "" {
		o.Port = "53"
	}
	resolver := dns.NewResolver(o.Timeout, o.Resolver)
	defer dns.CloseIdleConnections(resolver)
	var res Result

	lookupCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	servers, err := resolver.LookupNS(lookupCtx, target+".")
	cancel()
	res.Queries++
	// Go reports an answer without NS records as a not-found error, not as
	// an empty list, so "no name servers" is told apart by the error (#347).
	var de *net.DNSError
	switch {
	case err == nil && len(servers) > 0:
	case err == nil || errors.As(err, &de) && de.IsNotFound:
		res.Err = "no name servers found for " + target
		return res
	default:
		res.Err = "name server lookup failed: " + err.Error()
		return res
	}
	if len(servers) > MaxServers {
		servers = servers[:MaxServers]
	}

	names := map[string]struct{}{}
	transferTimeout := max(MinTimeout, o.Timeout)
	for _, ns := range servers {
		host := strings.ToLower(strings.TrimSuffix(ns.Host, "."))
		lookupCtx, cancel := context.WithTimeout(ctx, o.Timeout)
		addrs, err := resolver.LookupHost(lookupCtx, host+".")
		cancel()
		res.Queries += 2 // A and AAAA
		if err != nil {
			logf(o.Debug, "-axfr: cannot resolve name server %s: %v", host, err)
			continue
		}
		if len(addrs) > AddrsPerServer {
			addrs = addrs[:AddrsPerServer]
		}
		for _, addr := range addrs {
			if ctx.Err() != nil {
				return res
			}
			if res.Denial == "" {
				res.Queries++
				res.Denial = probeDenial(ctx, o, host, addr, target)
			}
			res.Tried++
			res.Queries++
			got, err := dns.Transfer(ctx, net.JoinHostPort(addr, o.Port), target, transferTimeout)
			if err != nil {
				if errors.Is(err, dns.ErrTransferRefused) {
					logf(o.Debug, "-axfr: %s (%s): %v", host, addr, err)
				} else {
					logf(o.Info, "-axfr: %s (%s): %v", host, addr, err)
				}
				continue
			}
			res.Allowed = append(res.Allowed, host)
			for _, n := range got {
				names[strings.TrimSuffix(n, "."+target)] = struct{}{}
			}
			logf(o.Info, "Zone transfer: %s (%s) allowed AXFR of %s: %d names. Anyone can list this zone; restrict transfers to your secondaries.", host, addr, target, len(got))
			break // one address of a server is enough
		}
	}
	for n := range names {
		res.Names = append(res.Names, n)
	}
	sort.Strings(res.Names)
	return res
}
