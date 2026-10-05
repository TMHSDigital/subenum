package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Pool health thresholds (#69).
const (
	poolHealthMinLookups = 20               // lookups before a resolver can be benched
	poolHealthFailPct    = 50               // failure share that benches a resolver
	poolBenchFor         = 30 * time.Second // how long a benched resolver sits out
)

// PoolResolver is one member of a Pool.
type PoolResolver struct {
	Addr     string
	resolver *net.Resolver

	mu       sync.Mutex
	stats    ResolverStats
	window   int // lookups since the last health reset
	windowKO int // failures in that window
	until    time.Time
}

// ResolverStats is one pool member's accounting for the run-quality report.
type ResolverStats struct {
	Addr     string `json:"address"`
	Lookups  int64  `json:"lookups"`
	Found    int64  `json:"found"`
	NXDomain int64  `json:"nxdomain"`
	Failed   int64  `json:"failed"`  // timeout, refused or other
	Benched  int64  `json:"benched"` // times it was taken out of rotation
}

// Pool spreads lookups over several resolvers, round-robin over the healthy
// ones. A resolver whose recent failure rate passes poolHealthFailPct is
// benched for poolBenchFor, then given another chance.
type Pool struct {
	members []*PoolResolver
	mu      sync.Mutex
	next    int
	now     func() time.Time
}

// ParseResolverList parses resolver addresses, one per line or entry, as
// ip or ip:port (port 53 by default). Blank lines and # comments are skipped.
func ParseResolverList(lines []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if net.ParseIP(s) != nil {
			s = net.JoinHostPort(s, "53")
		}
		host, port, err := net.SplitHostPort(s)
		if err != nil || net.ParseIP(host) == nil || port == "" {
			return nil, fmt.Errorf("invalid resolver %q: want ip or ip:port", line)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}

// NewPool builds a pool of resolvers from NewResolver.
func NewPool(addrs []string, timeout time.Duration) *Pool {
	p := &Pool{now: time.Now}
	for _, a := range addrs {
		p.members = append(p.members, &PoolResolver{Addr: a, resolver: NewResolver(timeout, a), stats: ResolverStats{Addr: a}})
	}
	return p
}

// Size returns the number of resolvers in the pool.
func (p *Pool) Size() int { return len(p.members) }

// pick returns the next healthy resolver, skipping avoid when possible. When
// every resolver is benched, the one whose bench ends soonest is used.
func (p *Pool) pick(avoid *PoolResolver) *PoolResolver {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	n := len(p.members)
	var fallback *PoolResolver
	var fallbackUntil time.Time
	for i := 0; i < n; i++ {
		m := p.members[(p.next+i)%n]
		m.mu.Lock()
		until := m.until
		m.mu.Unlock()
		if now.Before(until) {
			if fallback == nil || until.Before(fallbackUntil) {
				fallback, fallbackUntil = m, until
			}
			continue
		}
		if m == avoid && n > 1 {
			continue
		}
		p.next = (p.next + i + 1) % n
		return m
	}
	if fallback != nil {
		return fallback
	}
	return avoid
}

// report records a lookup's outcome and benches the resolver if it is failing.
func (p *Pool) report(m *PoolResolver, o Outcome) {
	if o == OutcomeCanceled {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.Lookups++
	m.window++
	switch o {
	case OutcomeFound:
		m.stats.Found++
	case OutcomeNXDomain:
		m.stats.NXDomain++
	default:
		m.stats.Failed++
		m.windowKO++
	}
	if m.window >= poolHealthMinLookups {
		if m.windowKO*100 > m.window*poolHealthFailPct {
			m.until = p.now().Add(poolBenchFor)
			m.stats.Benched++
		}
		m.window, m.windowKO = 0, 0
	}
}

// Resolve looks domain up through the pool, up to attempts times, each
// attempt on a different healthy resolver where possible. It returns the
// records, the outcome of the last attempt, and the resolver that answered.
func (p *Pool) Resolve(ctx context.Context, domain string, timeout time.Duration, logf Logf, attempts int, types []string) ([]Record, Outcome, string) {
	var last *PoolResolver
	outcome := OutcomeOther
	for attempt := 0; attempt < max(attempts, 1); attempt++ {
		if ctx.Err() != nil {
			return nil, OutcomeCanceled, ""
		}
		m := p.pick(last)
		last = m
		var recs []Record
		recs, outcome = ResolveDomainWithRetry(ctx, m.resolver, domain, timeout, logf, 1, types)
		p.report(m, outcome)
		switch outcome {
		case OutcomeFound:
			return recs, outcome, m.Addr
		case OutcomeNXDomain, OutcomeCanceled:
			return nil, outcome, m.Addr
		}
	}
	return nil, outcome, ""
}

// Stats returns a snapshot of every member's accounting, in pool order.
func (p *Pool) Stats() []ResolverStats {
	out := make([]ResolverStats, 0, len(p.members))
	for _, m := range p.members {
		m.mu.Lock()
		out = append(out, m.stats)
		m.mu.Unlock()
	}
	return out
}
