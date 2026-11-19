// Package axfr tries a full zone transfer of a domain from each of its name
// servers, and probes how the zone proves a name does not exist. The CLI's
// -axfr and the library's ZoneTransfer and ProbeZone both run it (#314).
package axfr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
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
	// Skip, when set, reports name server hosts that are out of scope
	// (-exclude): they are neither resolved nor contacted (#372).
	Skip func(host string) bool
	// Server, when set ("host:port"), receives every transfer and the
	// denial probe in place of the name servers' addresses, which are still
	// looked up: a lab run sends them to its local server, so nothing leaves
	// the machine (#434).
	Server string
}

// endpoint is where a request meant for a name server address goes.
func (o Options) endpoint(addr string) string {
	if o.Server != "" {
		return o.Server
	}
	return net.JoinHostPort(addr, o.Port)
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
	d, err := dns.ProbeDenial(ctx, o.endpoint(addr), target, o.Timeout)
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

	// Resolve the servers, and probe the denial at the first address that
	// answers, in order.
	var attempts []*attempt
	for _, ns := range servers {
		host := strings.ToLower(strings.TrimSuffix(ns.Host, "."))
		if o.Skip != nil && o.Skip(host) {
			logf(o.Debug, "-axfr: skipping name server %s: it is out of scope", host)
			continue
		}
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
		attempts = append(attempts, &attempt{host: host, addrs: addrs})
	}
	for _, a := range attempts {
		for _, addr := range a.addrs {
			if res.Denial != "" || ctx.Err() != nil {
				break
			}
			res.Queries++
			res.Denial = probeDenial(ctx, o, a.host, addr, target)
		}
	}

	// Ask every server at once (#365): one that silently drops TCP/53 costs
	// a whole transfer timeout, and asking them in turn added those up. Each
	// server's addresses are still tried in order, and what each reports is
	// printed in server order once all are done.
	transferTimeout := max(MinTimeout, o.Timeout)
	var wg sync.WaitGroup
	for _, a := range attempts {
		wg.Go(func() { a.transfer(ctx, o, target, transferTimeout) })
	}
	wg.Wait()
	// The names kept over all servers are bounded like one transfer's, so
	// eight servers cannot add eight times as many candidates.
	names := map[string]struct{}{}
	capped := false
	for _, a := range attempts {
		for _, l := range a.logs {
			logf(l.f, "%s", l.msg)
		}
		res.Tried += a.tried
		res.Queries += int64(a.tried)
		if a.allowed {
			res.Allowed = append(res.Allowed, a.host)
			for _, n := range a.got {
				n = strings.TrimSuffix(n, "."+target)
				if _, ok := names[n]; !ok && len(names) >= dns.MaxTransferNames {
					capped = true
					break
				}
				names[n] = struct{}{}
			}
			a.got = nil
		}
	}
	if capped {
		logf(o.Info, "-axfr: the transfers gave more than %d names; only the first %d are used", dns.MaxTransferNames, dns.MaxTransferNames)
	}
	for n := range names {
		res.Names = append(res.Names, n)
	}
	sort.Strings(res.Names)
	return res
}

// attempt is one name server's zone transfer, run beside the others.
type attempt struct {
	host  string
	addrs []string

	tried   int // addresses asked
	allowed bool
	got     []string // the zone, when an address allowed the transfer
	logs    []logLine
}

// logLine is a message held until every transfer is done, so they print in
// server order.
type logLine struct {
	f   func(string, ...any)
	msg string
}

func (a *attempt) logf(f func(string, ...any), format string, args ...any) {
	if f != nil {
		a.logs = append(a.logs, logLine{f, fmt.Sprintf(format, args...)})
	}
}

// transfer asks a's addresses in turn until one allows the transfer.
func (a *attempt) transfer(ctx context.Context, o Options, target string, timeout time.Duration) {
	for _, addr := range a.addrs {
		if ctx.Err() != nil {
			return
		}
		a.tried++
		got, err := dns.Transfer(ctx, o.endpoint(addr), target, timeout)
		if errors.Is(err, dns.ErrTransferTruncated) {
			a.allowed, a.got = true, got
			a.logf(o.Info, "Zone transfer: %s (%s) allowed AXFR of %s, but it was stopped: %v. Anyone can list this zone; restrict transfers to your secondaries.", a.host, addr, target, err)
			return
		}
		if err != nil {
			if errors.Is(err, dns.ErrTransferRefused) {
				a.logf(o.Debug, "-axfr: %s (%s): %v", a.host, addr, err)
			} else {
				a.logf(o.Info, "-axfr: %s (%s): %v", a.host, addr, err)
			}
			continue
		}
		a.allowed, a.got = true, got
		a.logf(o.Info, "Zone transfer: %s (%s) allowed AXFR of %s: %d names. Anyone can list this zone; restrict transfers to your secondaries.", a.host, addr, target, len(got))
		return // one address of a server is enough
	}
}
