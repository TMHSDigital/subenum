package cli

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/validate"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// ptrResult is a target's -ptr pass (#436): the PTR lookups of the public
// addresses found, and the scan of the names under the target they gave.
type ptrResult struct {
	addresses  int   // addresses looked up
	queries    int64 // PTR queries sent, retries included
	candidates int   // names the answers gave that were tested
	expired    bool  // -max-duration ran out before every address was looked up
	// pass is the scan of the candidates; zero when there were none.
	pass targetResult
}

// unfinished reports whether the pass stopped with addresses or names left,
// on -max-duration or a reliability abort.
func (p *ptrResult) unfinished() bool {
	return p.expired || p.pass.unfinished()
}

// ptrHit reports whether a result is one the -ptr pass found.
func ptrHit(r output.Result) bool {
	return slices.Equal(r.Sources, candidates.FromPTR)
}

// ptrAddresses returns the unique public A and AAAA values of results,
// sorted. Loopback, private, link-local, unspecified and CGNAT addresses
// (internal_address, #218) are left out, as are the wildcard fingerprint's:
// their PTR records belong to no name the scan found.
func ptrAddresses(results []output.Result, fingerprints ...[]dns.Record) []string {
	skip := map[string]bool{}
	for _, fp := range fingerprints {
		for _, r := range fp {
			skip[r.Value] = true
		}
	}
	set := map[netip.Addr]bool{}
	for _, res := range results {
		for _, r := range res.Records {
			if r.Type != "A" && r.Type != "AAAA" {
				continue
			}
			a, err := netip.ParseAddr(r.Value)
			if err != nil || skip[r.Value] || dns.AddressScope(r.Value) != "" || a.Unmap().IsMulticast() {
				continue
			}
			set[a.Unmap()] = true
		}
	}
	out := make([]netip.Addr, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	addrs := make([]string, len(out))
	for i, a := range out {
		addrs[i] = a.String()
	}
	return addrs
}

// ptrLookups is what lookupPTRs got: every name the answers gave, and how
// the lookups went.
type ptrLookups struct {
	names    []string
	asked    int
	queries  int64
	excluded int  // addresses whose reverse name -exclude rules out
	capped   int  // addresses left out by -max-queries
	expired  bool // -max-duration ran out first
}

// lookupPTRs asks for the PTR records of addrs: up to -t at a time, paced
// by -rate (and -rate-per-resolver through the -r pool), at most
// -max-queries addresses, none past -max-duration, and none whose reverse
// name -exclude rules out.
func lookupPTRs(ctx context.Context, s *session, addrs []string) ptrLookups {
	var res ptrLookups
	excluded := scan.Excluder(s.in.excludes)
	todo := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if rev, err := dns.ReverseName(a); err != nil || excluded(rev) {
			res.excluded++
			continue
		}
		todo = append(todo, a)
	}
	if m := s.f.maxQueries; m > 0 && len(todo) > m {
		res.capped = len(todo) - m
		todo = todo[:m]
	}
	timeout := time.Duration(s.f.timeoutMs) * time.Millisecond
	server := s.f.dnsServer
	if normalized, err := validate.NormalizeDNSServer(server); err == nil {
		server = normalized
	}
	l := dns.Lookup{Resolver: dns.NewResolver(timeout, server), Timeout: timeout}
	defer dns.CloseIdleConnections(l.Resolver)
	var sent atomic.Int64
	ctx = dns.WithQueryCounter(dns.WithLimiter(ctx, dns.NewRateLimiter(s.f.rate)), &sent)

	var (
		mu      sync.Mutex
		names   = map[string]bool{}
		asked   atomic.Int64
		expired atomic.Bool
		wg      sync.WaitGroup
	)
	next := make(chan string)
	for range max(min(s.f.concurrency, len(todo)), 1) {
		wg.Go(func() {
			for a := range next {
				if !s.in.deadline.IsZero() && !time.Now().Before(s.in.deadline) {
					expired.Store(true)
					continue
				}
				if ctx.Err() != nil {
					continue
				}
				asked.Add(1)
				var got []string
				if s.in.pool != nil {
					got, _ = s.in.pool.LookupPTR(ctx, l, a)
				} else {
					got, _ = l.LookupPTR(ctx, a)
				}
				mu.Lock()
				for _, n := range got {
					names[n] = true
				}
				mu.Unlock()
			}
		})
	}
	for _, a := range todo {
		next <- a
	}
	close(next)
	wg.Wait()
	for n := range names {
		res.names = append(res.names, n)
	}
	slices.Sort(res.names)
	res.asked, res.queries, res.expired = int(asked.Load()), sent.Load(), expired.Load()
	return res
}

// ptrCandidates returns the names under target, relative to it, that are in
// scope, not candidates of the main pass (entries and extra: already
// tested) and not found already.
func ptrCandidates(target string, names, entries, extra []string, found []output.Result, excludes []string) []string {
	have := make(map[string]bool, len(found))
	for _, r := range found {
		have[strings.ToLower(r.Subdomain)] = true
	}
	excluded := scan.Excluder(excludes)
	var rel []string
	for _, n := range names {
		r, ok := strings.CutSuffix(n, "."+target)
		if !ok || r == "" || have[n] || excluded(n) {
			continue
		}
		rel = append(rel, r)
	}
	built, _, _ := wordlist.Build(rel, target)
	return wordlist.NotIn(wordlist.NotIn(built, entries), extra)
}

// runPTRPass is the -ptr pass of a target (#436): after the main pass and
// any -permute pass, it looks up the PTR records of the public addresses
// found, and scans the names under the target they give as a flat pass, so
// a stale PTR record is not reported, and the results carry sources ["ptr"].
// The scan is fully guarded (preflight, wildcard filtering, -rate,
// -max-queries, -max-duration, -exclude). A resumed run does it again: its
// lookups are few, and names it already found are not reported twice.
func runPTRPass(ctx context.Context, s *session, target string, entries, extra []string, fingerprints ...[]dns.Record) *ptrResult {
	out := s.out
	res := &ptrResult{}
	if s.f.testMode {
		return res
	}
	addrs := ptrAddresses(s.targetResults.results(), fingerprints...)
	if len(addrs) == 0 {
		out.Info("PTR pass for %s: no public addresses to look up", target)
		return res
	}
	lk := lookupPTRs(ctx, s, addrs)
	res.addresses, res.queries, res.expired = lk.asked, lk.queries, lk.expired
	if lk.excluded > 0 {
		out.Info("PTR pass for %s: skipped %d addresses whose reverse names -exclude rules out", target, lk.excluded)
	}
	if lk.capped > 0 {
		out.Info("PTR pass for %s: the -max-queries budget of %d left %d addresses unasked", target, s.f.maxQueries, lk.capped)
	}
	if lk.expired {
		out.Info("PTR pass for %s: -max-duration ran out after %d of %d addresses", target, lk.asked, len(addrs))
	}
	if ctx.Err() != nil {
		return res
	}
	cands := ptrCandidates(target, lk.names, entries, extra, s.targetResults.results(), s.in.excludes)
	res.candidates = len(cands)
	out.Info("PTR pass for %s: %d addresses gave %d names, %d of them new under the target", target, lk.asked, len(lk.names), len(cands))
	if len(cands) == 0 {
		return res
	}
	s.refound = refoundCount{}
	res.pass = scanTarget(ctx, s, scanPass{domain: target, entries: cands, maxQueries: s.f.maxQueries, flat: true}, s.emitPTR)
	if s.refound.names > 0 && res.pass.done {
		res.pass.final = withoutRefound(res.pass.final, s.refound)
	}
	return res
}
