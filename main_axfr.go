package main

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
)

// Zone transfer bounds (#85): a target with many name servers, or name
// servers with many addresses, cannot turn -axfr into a flood.
const (
	axfrMaxServers     = 8
	axfrMinTimeout     = 10 * time.Second
	axfrAddrsPerServer = 2
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

// probeDenial asks one authoritative address how target proves a name does
// not exist (#234). Plain NSEC means anyone can list the zone by walking it,
// which is reported like an allowed transfer. A failed probe is "" so the
// next address is tried.
func probeDenial(ctx context.Context, f cliFlags, host, addr, port, target string, timeout time.Duration, out *output.Writer) dns.Denial {
	d, err := dns.ProbeDenial(ctx, net.JoinHostPort(addr, port), target, timeout)
	if err != nil {
		if f.verbose {
			out.Info("-axfr: DNSSEC denial probe to %s (%s): %v", host, addr, err)
		}
		return ""
	}
	if d == dns.DenialNSEC {
		out.Info("Zone walkable: %s signs %s with plain NSEC, so anyone can list every name by walking it. NSEC3 would hide them.", host, target)
	} else if f.verbose {
		out.Info("-axfr: %s proves absent names with %s; the zone cannot be walked", target, d)
	}
	return d
}

// zoneTransfer tries a full zone transfer (AXFR) of target from each of its
// name servers, found through the trusted resolver. A server that allows it
// gives every name in the zone in one query; most refuse, which is the
// correct configuration and not reported as an error. A resumed run reuses
// the names the interrupted run got, so its candidate list matches.
func zoneTransfer(ctx context.Context, f cliFlags, port, target string, saved *resumeTarget, out *output.Writer) targetAXFR {
	if saved != nil && saved.AXFRDone {
		return targetAXFR{names: saved.AXFR, allowed: saved.AXFRServers, denial: dns.Denial(saved.Denial), done: true}
	}
	timeout := time.Duration(f.timeoutMs) * time.Millisecond
	resolver := dns.NewResolver(timeout, f.dnsServer)
	defer dns.CloseIdleConnections(resolver)
	res := targetAXFR{done: true}

	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	servers, err := resolver.LookupNS(lookupCtx, target+".")
	cancel()
	res.queries++
	if err != nil || len(servers) == 0 {
		res.err = "no name servers found for " + target
		if err != nil {
			res.err = "name server lookup failed: " + err.Error()
		}
		out.Info("Warning: -axfr: %s; scanning %s without a zone transfer", res.err, target)
		return res
	}
	if len(servers) > axfrMaxServers {
		servers = servers[:axfrMaxServers]
	}

	names := map[string]struct{}{}
	transferTimeout := max(axfrMinTimeout, timeout)
	for _, ns := range servers {
		host := strings.ToLower(strings.TrimSuffix(ns.Host, "."))
		lookupCtx, cancel := context.WithTimeout(ctx, timeout)
		addrs, err := resolver.LookupHost(lookupCtx, host+".")
		cancel()
		res.queries += 2 // A and AAAA
		if err != nil {
			if f.verbose {
				out.Info("-axfr: cannot resolve name server %s: %v", host, err)
			}
			continue
		}
		if len(addrs) > axfrAddrsPerServer {
			addrs = addrs[:axfrAddrsPerServer]
		}
		for _, addr := range addrs {
			if ctx.Err() != nil {
				return res
			}
			if res.denial == "" {
				res.queries++
				res.denial = probeDenial(ctx, f, host, addr, port, target, timeout, out)
			}
			res.tried++
			res.queries++
			got, err := dns.Transfer(ctx, net.JoinHostPort(addr, port), target, transferTimeout)
			if err != nil {
				if f.verbose || !errors.Is(err, dns.ErrTransferRefused) {
					out.Info("-axfr: %s (%s): %v", host, addr, err)
				}
				continue
			}
			res.allowed = append(res.allowed, host)
			for _, n := range got {
				names[strings.TrimSuffix(n, "."+target)] = struct{}{}
			}
			out.Info("Zone transfer: %s (%s) allowed AXFR of %s: %d names. Anyone can list this zone; restrict transfers to your secondaries.", host, addr, target, len(got))
			break // one address of a server is enough
		}
	}
	for n := range names {
		res.names = append(res.names, n)
	}
	sort.Strings(res.names)
	if len(res.allowed) == 0 && f.verbose {
		out.Info("-axfr: no name server of %s allowed a zone transfer (%d addresses asked)", target, res.tried)
	}
	return res
}
