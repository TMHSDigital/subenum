package scan

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/TMHSDigital/subenum/internal/dns"
)

type wildcardCache struct {
	mu    sync.Mutex
	known map[string]bool
}

func (c *wildcardCache) isWildcard(ctx context.Context, cfg Config, parent string) (bool, error) {
	c.mu.Lock()
	if v, ok := c.known[parent]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	is, _, err := cfg.lookup(nil).CheckWildcard(ctx, parent)
	if err != nil {
		return false, err // never cache an inconclusive check
	}
	c.mu.Lock()
	if c.known == nil {
		c.known = make(map[string]bool)
	}
	c.known[parent] = is
	c.mu.Unlock()
	return is, nil
}

// fingerprint is the root wildcard's known answers. A result whose records
// all appear in it is a wildcard answer. Near-miss results grow it with fresh
// probes (see revalidate), so it is shared by the workers and locked.
type fingerprint struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

func newFingerprint(recs []dns.Record) *fingerprint {
	f := &fingerprint{set: make(map[string]struct{}, len(recs))}
	f.add(recs)
	return f
}

func (f *fingerprint) add(recs []dns.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range recs {
		f.set[dns.RecordKey(r)] = struct{}{}
	}
}

// records returns the fingerprint's records in a stable order.
func (f *fingerprint) records() []dns.Record {
	f.mu.RLock()
	keys := make([]string, 0, len(f.set))
	for k := range f.set {
		keys = append(keys, k)
	}
	f.mu.RUnlock()
	sort.Strings(keys)
	out := make([]dns.Record, 0, len(keys))
	for _, k := range keys {
		typ, val, _ := strings.Cut(k, "\x00")
		out = append(out, dns.Record{Type: typ, Value: val})
	}
	return out
}

// match reports whether every record of got is a known wildcard answer
// (covered) and whether at least one is (overlaps). An empty fingerprint or
// result never matches.
func (f *fingerprint) match(got []dns.Record) (covered, overlaps bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.set) == 0 || len(got) == 0 {
		return false, false
	}
	covered = true
	for _, r := range got {
		if _, ok := f.set[dns.RecordKey(r)]; ok {
			overlaps = true
		} else {
			covered = false
		}
	}
	return covered, overlaps
}

// nearMissProbes is how many fresh random labels re-validate a result that
// shares some but not all records with the wildcard fingerprint (#48).
const nearMissProbes = 2

// isWildcardAnswer reports whether records are a wildcard answer for name. A
// result that only partly matches the fingerprint is a near miss, typical of
// a wildcard served from a rotating pool: fresh random labels under the same
// parent are probed, their answers join the fingerprint, and the result is
// checked again. Results that share nothing with the fingerprint (real names)
// cost no extra queries.
func isWildcardAnswer(ctx context.Context, cfg Config, fp *fingerprint, name string, records []dns.Record) bool {
	covered, overlaps := fp.match(records)
	if covered || !overlaps || !cfg.live() {
		return covered
	}
	parent := name
	if i := strings.IndexByte(name, '.'); i >= 0 {
		parent = name[i+1:]
	}
	for i := 0; i < nearMissProbes; i++ {
		recs, _ := cfg.resolve(ctx, dns.RandomLabel()+"."+parent, nil)
		fp.add(recs)
		if covered, _ = fp.match(records); covered {
			return true
		}
	}
	return false
}
