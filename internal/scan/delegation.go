package scan

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/TMHSDigital/subenum/internal/axfr"
	"github.com/TMHSDigital/subenum/internal/dns"
)

// parentZone checks the delegation of a name whose lookup ended SERVFAIL at
// the target zone's own name servers (#406). A recursive resolver asked
// about a subzone whose every name server is gone answers SERVFAIL rather
// than the delegation, so the name never reaches the dangling-NS hint. The
// zone's servers still hand out the delegation when asked without
// recursion; when the name servers it names do not exist, the name is a
// takeover candidate like any other dangling delegation.
//
// The zone's name servers are looked up once per scan (a scan has one
// zone, its target), with the -axfr lookup. Every query the checks send
// takes a -rate slot and is counted in Stats.QueriesSent, and together they
// stop at Config.MaxQueries.
type parentZone struct {
	cfg Config

	once      sync.Once
	endpoints []string // where the delegation queries go
	err       string   // why there are none

	checks  atomic.Int64 // names whose delegation was asked for
	queries atomic.Int64 // queries sent: the name server lookups and the delegation queries

	noticeOnce sync.Once
}

// newParentZone returns the checker for cfg's scan, or nil when the scan
// cannot use one: simulated or hooked lookups, or NS not among the types.
func newParentZone(cfg Config) *parentZone {
	if !cfg.live() || !slices.Contains(cfg.Types, "NS") {
		return nil
	}
	return &parentZone{cfg: cfg}
}

// servers looks up the zone's name servers, once.
func (p *parentZone) servers(ctx context.Context) ([]string, string) {
	p.once.Do(func() {
		cfg := p.cfg
		if cfg.ZoneServer != "" {
			// A lab: its server answers for the zone, whatever name
			// servers the scenario lists, or none.
			p.endpoints = []string{cfg.ZoneServer}
			return
		}
		servers, queries, errMsg := axfr.NameServers(ctx, cfg.Resolver, cfg.Domain, axfr.Options{Timeout: cfg.Timeout, Skip: cfg.scope.excluded})
		p.queries.Add(queries)
		if errMsg != "" {
			p.err = errMsg
			return
		}
		for _, ns := range servers {
			for _, addr := range ns.Addrs {
				if ep := net.JoinHostPort(addr, "53"); !slices.Contains(p.endpoints, ep) {
					p.endpoints = append(p.endpoints, ep)
				}
			}
		}
		if len(p.endpoints) == 0 {
			p.err = "none of the name servers of " + cfg.Domain + " could be resolved"
		}
	})
	return p.endpoints, p.err
}

// overBudget reports whether the checks have used up Config.MaxQueries.
func (p *parentZone) overBudget() bool {
	return p.cfg.MaxQueries > 0 && p.queries.Load() >= int64(p.cfg.MaxQueries)
}

// delegation asks the zone's name servers which name servers name is
// delegated to, in turn until one answers, and returns them as NS records;
// nil when none answered or the name is not delegated. notice reports, once,
// why no check could be made.
func (p *parentZone) delegation(ctx context.Context, name string, notice func(string)) []dns.Record {
	cfg := p.cfg
	if cfg.scope.excluded(name) || cfg.pastDeadline() || p.overBudget() || ctx.Err() != nil {
		return nil
	}
	endpoints, errMsg := p.servers(ctx)
	if errMsg != "" {
		if ctx.Err() == nil {
			p.noticeOnce.Do(func() {
				notice(fmt.Sprintf("cannot ask the name servers of %s about names that failed with SERVFAIL: %s", cfg.Domain, errMsg))
			})
		}
		return nil
	}
	p.checks.Add(1)
	logf := cfg.logf()
	for _, ep := range endpoints {
		if p.overBudget() || ctx.Err() != nil {
			return nil
		}
		hosts, sent, err := dns.AskDelegation(ctx, ep, name, cfg.Timeout)
		p.queries.Add(int64(sent))
		if err != nil {
			if logf != nil {
				logf("[delegation] %s: asking %s: %v", name, ep, err)
			}
			continue
		}
		if logf != nil {
			logf("[delegation] %s: %s delegates it to [%s]", name, ep, strings.Join(hosts, " "))
		}
		var records []dns.Record
		for _, h := range hosts {
			records = append(records, dns.Record{Type: "NS", Value: h})
		}
		return records
	}
	return nil
}

// danglingDelegation reports, for a name whose lookup ended SERVFAIL (an
// Other outcome), the NS records of its delegation when the zone's name
// servers delegate it to a name server that does not exist. Those targets
// are resolved through the trusted resolver, by the takeover cache, as the
// dangling-NS hint of any result is (#194).
func (s *scanState) danglingDelegation(ctx context.Context, name string) ([]dns.Record, bool) {
	if s.parent == nil {
		return nil, false
	}
	records := s.parent.delegation(ctx, name, func(msg string) {
		s.events <- Event{Kind: EventNotice, Notice: NoticeSkip, Message: msg}
	})
	if len(records) == 0 {
		return nil, false
	}
	if s.cfg.takeover.Hint(ctx, s.cfg.lookup(nil), records) != dns.DanglingNS {
		return nil, false
	}
	return records, true
}
