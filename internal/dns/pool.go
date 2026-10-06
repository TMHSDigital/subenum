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

// Pool honesty checks (#105). A member's NXDOMAIN answers are taken at face
// value only while it is trusted: it last answered a canary (a name the
// trusted resolver confirmed exists) correctly, within poolCanaryEvery of
// its lookups. An untrusted member's NXDOMAIN gets a second opinion from
// another member. Every contradiction (a hidden name, or a hit the trusted
// resolver denies) counts against the member, and poolFlagAfter of them take
// it out of rotation for the rest of the run.
const (
	poolCanaryEvery = 25 // lookups between canary checks of a trusted member
	poolFlagAfter   = 3  // contradictions that flag a member as lying
	poolMaxCanaries = 32 // known-existing names kept for canary checks
)

// PoolResolver is one member of a Pool.
type PoolResolver struct {
	Addr     string
	resolver *net.Resolver

	mu          sync.Mutex
	stats       ResolverStats
	window      int // lookups since the last health reset
	windowKO    int // failures in that window
	until       time.Time
	trusted     bool // passed its last canary check
	sinceCanary int  // lookups since the last canary check
	canaryBusy  bool // a canary check is in flight
}

// ResolverStats is one pool member's accounting for the run-quality report.
type ResolverStats struct {
	Addr     string `json:"address"`
	Lookups  int64  `json:"lookups"`
	Found    int64  `json:"found"`
	NXDomain int64  `json:"nxdomain"`
	Failed   int64  `json:"failed"`  // timeout, refused or other
	Benched  int64  `json:"benched"` // times it was taken out of rotation
	// Honesty checks (#105).
	Canaries     int64 `json:"canaries"`     // canary checks answered
	Contradicted int64 `json:"contradicted"` // answers another resolver proved wrong
	Flagged      bool  `json:"flagged"`      // taken out of rotation as lying
}

// Pool spreads lookups over several resolvers, round-robin over the healthy
// ones. A resolver whose recent failure rate passes poolHealthFailPct is
// benched for poolBenchFor, then given another chance. One that is caught
// lying is flagged and never used again in the run.
type Pool struct {
	members []*PoolResolver
	mu      sync.Mutex
	next    int
	now     func() time.Time

	canaryMu   sync.Mutex
	canaries   []string
	canarySeen map[string]bool
	canaryNext int
}

// PoolAnswer is a pool lookup's result.
type PoolAnswer struct {
	Records []Record
	Outcome Outcome
	Addr    string // the resolver that answered; "" when none did
	// NoResolver is set when every member has been flagged as lying, so
	// the caller must use its trusted resolver instead.
	NoResolver bool

	member       *PoolResolver // answered
	contradicted *PoolResolver // answered NXDOMAIN, then another member found the name
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
	p := &Pool{now: time.Now, canarySeen: map[string]bool{}}
	for _, a := range addrs {
		p.members = append(p.members, &PoolResolver{Addr: a, resolver: NewResolver(timeout, a), stats: ResolverStats{Addr: a}})
	}
	return p
}

// Size returns the number of resolvers in the pool.
func (p *Pool) Size() int { return len(p.members) }

// AddCanary records a name the trusted resolver confirmed exists, for
// checking that pool members do not hide existing names.
func (p *Pool) AddCanary(name string) {
	p.canaryMu.Lock()
	defer p.canaryMu.Unlock()
	if p.canarySeen[name] || len(p.canaries) >= poolMaxCanaries {
		return
	}
	p.canarySeen[name] = true
	p.canaries = append(p.canaries, name)
}

// canary returns the next canary name, or "" when none is known yet.
func (p *Pool) canary() string {
	p.canaryMu.Lock()
	defer p.canaryMu.Unlock()
	if len(p.canaries) == 0 {
		return ""
	}
	name := p.canaries[p.canaryNext%len(p.canaries)]
	p.canaryNext++
	return name
}

// pick returns the next healthy resolver, skipping avoid when possible. When
// every usable resolver is benched, the one whose bench ends soonest is used.
// Flagged resolvers are never returned; nil means none is left.
func (p *Pool) pick(avoid *PoolResolver) *PoolResolver {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	n := len(p.members)
	var fallback, avoided *PoolResolver
	var fallbackUntil time.Time
	for i := 0; i < n; i++ {
		m := p.members[(p.next+i)%n]
		m.mu.Lock()
		until, flagged := m.until, m.stats.Flagged
		m.mu.Unlock()
		switch {
		case flagged:
			continue
		case now.Before(until):
			if fallback == nil || until.Before(fallbackUntil) {
				fallback, fallbackUntil = m, until
			}
			continue
		case m == avoid:
			avoided = m
			continue
		}
		p.next = (p.next + i + 1) % n
		return m
	}
	if fallback != nil {
		return fallback
	}
	return avoided
}

// pickHealthy returns the next member other than avoid that is neither
// benched nor flagged, or nil.
func (p *Pool) pickHealthy(avoid *PoolResolver) *PoolResolver {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	n := len(p.members)
	for i := 0; i < n; i++ {
		m := p.members[(p.next+i)%n]
		if m == avoid {
			continue
		}
		m.mu.Lock()
		usable := !m.stats.Flagged && !now.Before(m.until)
		m.mu.Unlock()
		if usable {
			p.next = (p.next + i + 1) % n
			return m
		}
	}
	return nil
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
	m.sinceCanary++
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

// contradict records that m gave an answer another resolver proved wrong.
func (p *Pool) contradict(m *PoolResolver) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trusted = false
	m.stats.Contradicted++
	if m.stats.Contradicted >= poolFlagAfter {
		m.stats.Flagged = true
	}
}

// Disagree reports that the trusted resolver contradicted a pool answer: a
// hit it says does not exist was injected by the member that answered, and a
// name it confirms was hidden by the member whose NXDOMAIN the pool
// overruled. Either counts against that member (#105).
func (p *Pool) Disagree(a PoolAnswer, trusted Outcome) {
	switch trusted {
	case OutcomeFound:
		p.contradict(a.contradicted)
	case OutcomeNXDomain:
		p.contradict(a.member)
	}
}

// checkCanary asks m about a known-existing name when a check is due: always
// while m is untrusted, else every poolCanaryEvery lookups. An NXDOMAIN
// answer is a contradiction. Failed checks change nothing.
func (p *Pool) checkCanary(ctx context.Context, m *PoolResolver, timeout time.Duration, types []string) {
	m.mu.Lock()
	due := !m.canaryBusy && (!m.trusted || m.sinceCanary >= poolCanaryEvery)
	if due {
		m.canaryBusy = true
	}
	m.mu.Unlock()
	if !due {
		return
	}
	name := p.canary()
	if name == "" {
		m.mu.Lock()
		m.canaryBusy = false
		m.mu.Unlock()
		return
	}
	_, o := ResolveDomainWithRetry(ctx, m.resolver, name, timeout, nil, 1, types)
	m.mu.Lock()
	m.canaryBusy = false
	if o == OutcomeFound || o == OutcomeNXDomain {
		m.stats.Canaries++
		m.sinceCanary = 0
		m.trusted = o == OutcomeFound
	}
	m.mu.Unlock()
	if o == OutcomeNXDomain {
		p.contradict(m)
	}
}

// Resolve looks domain up through the pool, up to attempts times, each
// attempt on a different healthy resolver where possible. An NXDOMAIN from a
// member that has not passed a canary check is asked of a second member; if
// that one finds the name, its answer is returned and the first member is
// recorded as contradicted for the caller's Disagree.
func (p *Pool) Resolve(ctx context.Context, domain string, timeout time.Duration, logf Logf, attempts int, types []string) PoolAnswer {
	var last *PoolResolver
	outcome := OutcomeOther
	for attempt := 0; attempt < max(attempts, 1); attempt++ {
		if ctx.Err() != nil {
			return PoolAnswer{Outcome: OutcomeCanceled}
		}
		m := p.pick(last)
		if m == nil {
			return PoolAnswer{Outcome: OutcomeOther, NoResolver: true}
		}
		last = m
		p.checkCanary(ctx, m, timeout, types)
		var recs []Record
		recs, outcome = ResolveDomainWithRetry(ctx, m.resolver, domain, timeout, logf, 1, types)
		p.report(m, outcome)
		switch outcome {
		case OutcomeFound:
			return PoolAnswer{Records: recs, Outcome: outcome, Addr: m.Addr, member: m}
		case OutcomeNXDomain:
			return p.secondOpinion(ctx, m, domain, timeout, logf, types)
		case OutcomeCanceled:
			return PoolAnswer{Outcome: outcome, Addr: m.Addr, member: m}
		}
	}
	return PoolAnswer{Outcome: outcome}
}

// secondOpinion confirms an untrusted member's NXDOMAIN with another member.
func (p *Pool) secondOpinion(ctx context.Context, m *PoolResolver, domain string, timeout time.Duration, logf Logf, types []string) PoolAnswer {
	nx := PoolAnswer{Outcome: OutcomeNXDomain, Addr: m.Addr, member: m}
	m.mu.Lock()
	trusted := m.trusted
	m.mu.Unlock()
	if trusted {
		return nx
	}
	other := p.pickHealthy(m)
	if other == nil {
		return nx
	}
	recs, o := ResolveDomainWithRetry(ctx, other.resolver, domain, timeout, logf, 1, types)
	p.report(other, o)
	if o == OutcomeFound {
		return PoolAnswer{Records: recs, Outcome: o, Addr: other.Addr, member: other, contradicted: m}
	}
	return nx
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
