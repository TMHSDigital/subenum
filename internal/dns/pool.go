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
	trusted     bool      // passed its last canary check
	sinceCanary int       // lookups since the last canary check
	canaryBusy  bool      // a canary check is in flight
	free        time.Time // when its rate cap next allows a query (#196)
}

// ResolverStats is one pool member's accounting for the run-quality report.
type ResolverStats struct {
	Addr     string `json:"address"`
	Lookups  int64  `json:"lookups"`
	Found    int64  `json:"found"`
	NXDomain int64  `json:"nxdomain"`
	Failed   int64  `json:"failed"`  // timeout, refused or other
	Benched  int64  `json:"benched"` // times it was taken out of rotation
	// Throttled counts the times a lookup found its per-resolver rate cap
	// spent, and went to another member or waited (#196).
	Throttled int64 `json:"throttled"`
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
	// interval spaces the queries sent to any one member; 0 is uncapped
	// (#196). sleep waits out a reserved slot.
	interval time.Duration
	sleep    func(context.Context, time.Duration) error

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
	p := &Pool{now: time.Now, sleep: sleepCtx, canarySeen: map[string]bool{}}
	for _, a := range addrs {
		p.members = append(p.members, &PoolResolver{Addr: a, resolver: NewResolver(timeout, a), stats: ResolverStats{Addr: a}})
	}
	return p
}

// SetRatePerResolver caps the DNS queries sent to each member at perSecond,
// spaced like RateLimiter; perSecond <= 0 removes the cap. Lookups prefer a
// member whose cap has room and wait only when every member's is spent. A
// rate limiter on the lookup's context still applies, so the stricter of the
// two wins (#196). Call it before the pool is used.
func (p *Pool) SetRatePerResolver(perSecond int) {
	p.interval = 0
	if perSecond > 0 {
		p.interval = max(time.Second/time.Duration(perSecond), time.Nanosecond)
	}
}

// sleepCtx waits d, or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// capped reports whether m's rate cap has no room at now, counting it as
// throttled when so. The caller holds m.mu.
func (p *Pool) capped(m *PoolResolver, now time.Time) bool {
	if p.interval <= 0 || !now.Before(m.free) {
		return false
	}
	m.stats.Throttled++
	return true
}

// reserve takes queries slots of m's rate cap and waits for the first one
// (#196); the rest follow it back to back. It returns ctx's error if ctx
// ends first.
func (p *Pool) reserve(ctx context.Context, m *PoolResolver, queries int) error {
	if p.interval <= 0 {
		return ctx.Err()
	}
	m.mu.Lock()
	now := p.now()
	slot := m.free
	if slot.Before(now) {
		slot = now
	}
	m.free = slot.Add(time.Duration(max(queries, 1)) * p.interval)
	m.mu.Unlock()
	return p.sleep(ctx, slot.Sub(now))
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

// pick returns the next healthy resolver, skipping avoid when possible. The
// preference order is: healthy and not avoid, then avoid if it is healthy,
// then the healthy resolver whose rate cap frees up soonest (#196), then the
// benched resolver whose bench ends soonest. Flagged resolvers are never
// returned; nil means none is left.
func (p *Pool) pick(avoid *PoolResolver) *PoolResolver {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	n := len(p.members)
	var fallback, avoided, throttled *PoolResolver
	var fallbackUntil, throttledFree time.Time
	for i := 0; i < n; i++ {
		m := p.members[(p.next+i)%n]
		m.mu.Lock()
		until, flagged := m.until, m.stats.Flagged
		capped := !flagged && !now.Before(until) && p.capped(m, now)
		free := m.free
		m.mu.Unlock()
		switch {
		case flagged:
			continue
		case now.Before(until):
			if fallback == nil || until.Before(fallbackUntil) {
				fallback, fallbackUntil = m, until
			}
			continue
		case capped:
			if throttled == nil || free.Before(throttledFree) {
				throttled, throttledFree = m, free
			}
			continue
		case m == avoid:
			avoided = m
			continue
		}
		p.next = (p.next + i + 1) % n
		return m
	}
	switch {
	case avoided != nil:
		return avoided
	case throttled != nil:
		return throttled
	}
	return fallback
}

// pickHealthy returns the next member other than avoid that is neither
// benched nor flagged, preferring one whose rate cap has room, or nil.
func (p *Pool) pickHealthy(avoid *PoolResolver) *PoolResolver {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	n := len(p.members)
	var throttled *PoolResolver
	var throttledFree time.Time
	for i := 0; i < n; i++ {
		m := p.members[(p.next+i)%n]
		if m == avoid {
			continue
		}
		m.mu.Lock()
		usable := !m.stats.Flagged && !now.Before(m.until)
		capped := usable && p.capped(m, now)
		free := m.free
		m.mu.Unlock()
		switch {
		case capped:
			if throttled == nil || free.Before(throttledFree) {
				throttled, throttledFree = m, free
			}
		case usable:
			p.next = (p.next + i + 1) % n
			return m
		}
	}
	return throttled
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
func (p *Pool) checkCanary(ctx context.Context, m *PoolResolver, l Lookup) {
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
	if name == "" || p.reserve(ctx, m, QueriesFor(l.Types)) != nil {
		m.mu.Lock()
		m.canaryBusy = false
		m.mu.Unlock()
		return
	}
	quiet := m.lookup(l)
	quiet.Logf = nil
	_, o := quiet.Resolve(ctx, name)
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

// Resolve looks domain up through the pool, up to l.Attempts times, each
// attempt on a different healthy resolver where possible. l.Resolver is
// unused: each attempt is one lookup on a member's own resolver, with
// l.Timeout, l.Types and l.Logf. An NXDOMAIN from a
// member that has not passed a canary check is asked of a second member; if
// that one finds the name, its answer is returned and the first member is
// recorded as contradicted for the caller's Disagree.
func (p *Pool) Resolve(ctx context.Context, l Lookup, domain string) PoolAnswer {
	var last *PoolResolver
	outcome := OutcomeOther
	for attempt := 0; attempt < max(l.Attempts, 1); attempt++ {
		if ctx.Err() != nil {
			return PoolAnswer{Outcome: OutcomeCanceled}
		}
		m := p.pick(last)
		if m == nil {
			return PoolAnswer{Outcome: OutcomeOther, NoResolver: true}
		}
		last = m
		p.checkCanary(ctx, m, l)
		if p.reserve(ctx, m, QueriesFor(l.Types)) != nil {
			return PoolAnswer{Outcome: OutcomeCanceled}
		}
		var recs []Record
		recs, outcome = m.lookup(l).Resolve(ctx, domain)
		p.report(m, outcome)
		switch outcome {
		case OutcomeFound:
			return PoolAnswer{Records: recs, Outcome: outcome, Addr: m.Addr, member: m}
		case OutcomeNXDomain:
			return p.secondOpinion(ctx, m, l, domain)
		case OutcomeCanceled:
			return PoolAnswer{Outcome: outcome, Addr: m.Addr, member: m}
		}
	}
	return PoolAnswer{Outcome: outcome}
}

// secondOpinion confirms an untrusted member's NXDOMAIN with another member.
func (p *Pool) secondOpinion(ctx context.Context, m *PoolResolver, l Lookup, domain string) PoolAnswer {
	nx := PoolAnswer{Outcome: OutcomeNXDomain, Addr: m.Addr, member: m}
	m.mu.Lock()
	trusted := m.trusted
	m.mu.Unlock()
	if trusted {
		return nx
	}
	other := p.pickHealthy(m)
	if other == nil || p.reserve(ctx, other, QueriesFor(l.Types)) != nil {
		return nx
	}
	recs, o := other.lookup(l).Resolve(ctx, domain)
	p.report(other, o)
	if o == OutcomeFound {
		return PoolAnswer{Records: recs, Outcome: o, Addr: other.Addr, member: other, contradicted: m}
	}
	return nx
}

// lookup is l as one try on m's resolver.
func (m *PoolResolver) lookup(l Lookup) Lookup {
	l.Resolver, l.Attempts = m.resolver, 1
	return l
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
