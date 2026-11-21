package dns

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// chainServer serves example.test signed with plain NSEC over chain, its
// owner names in canonical order, the apex first: a query for a name that is
// not an owner gets NXDOMAIN with the NSEC record that covers it. next, when
// set, overrides the next name of an owner's record (a malformed chain).
// asked records every name queried.
func chainServer(t *testing.T, chain []string, next map[string]string) (*dnstest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		mu.Lock()
		asked = append(asked, q.Name)
		mu.Unlock()
		i, owner := slices.BinarySearchFunc(chain, q.Name, canonicalCompare)
		if owner {
			return dnstest.Reply{A: []string{"192.0.2.1"}}
		}
		prev := chain[i-1]
		n := chain[i%len(chain)]
		if o, ok := next[prev]; ok {
			n = o
		}
		return dnstest.Reply{RCode: 3, NSEC: []dnstest.NSEC{{Owner: prev, Next: n}}}
	})
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(asked)
	}
}

var testChain = []string{
	"example.test",
	"api.example.test",
	"corp.example.test",
	"a.corp.example.test",
	"vpn.corp.example.test",
	"*.dev.example.test",
	"www.example.test",
}

// TestWalkNSEC covers #437: a walk follows the chain from the apex back to
// it, one query per owner, and lists every owner except the apex and the
// wildcard.
func TestWalkNSEC(t *testing.T) {
	t.Parallel()
	srv, asked := chainServer(t, testChain, nil)
	res := WalkNSEC(context.Background(), srv.Addr, "Example.Test.", WalkOptions{Timeout: 5 * time.Second})
	want := []string{"a.corp", "api", "corp", "vpn.corp", "www"}
	if !slices.Equal(res.Names, want) || res.Stop != "" || res.Queries != int64(len(testChain)) {
		t.Errorf("walk = %+v, want names %v, no stop and %d queries", res, want, len(testChain))
	}
	if q := asked(); len(q) == 0 || q[0] != "\x00.example.test" {
		t.Errorf("first query %q, want \\000.example.test", q)
	}
}

// TestWalkNSECStops covers #437's bounds: a chain that loops back or leaves
// the zone, the query limit, a spent time budget and a refusing server each
// end the walk with a reason, keeping what it listed.
func TestWalkNSECStops(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		next  map[string]string
		opts  WalkOptions
		names []string
		stop  string
	}{
		{"loop", map[string]string{"corp.example.test": "api.example.test"}, WalkOptions{}, []string{"api", "corp"}, "does not sort after"},
		{"repeat", map[string]string{"api.example.test": "api.example.test"}, WalkOptions{}, []string{"api"}, "does not sort after"},
		{"outside", map[string]string{"api.example.test": "www.other.test"}, WalkOptions{}, []string{"api"}, "outside the zone"},
		{"limit", nil, WalkOptions{MaxQueries: 3}, []string{"a.corp", "api", "corp"}, "limit of 3 queries"},
		{"deadline", nil, WalkOptions{Deadline: time.Now().Add(-time.Second)}, nil, "time budget"},
	} {
		srv, asked := chainServer(t, testChain, c.next)
		c.opts.Timeout = 5 * time.Second
		res := WalkNSEC(context.Background(), srv.Addr, "example.test", c.opts)
		if !slices.Equal(res.Names, c.names) || !strings.Contains(res.Stop, c.stop) {
			t.Errorf("%s: walk = %+v, want names %v and a stop with %q", c.name, res, c.names, c.stop)
		}
		if n := int64(len(asked())); n != res.Queries {
			t.Errorf("%s: server got %d queries, walk counted %d", c.name, n, res.Queries)
		}
	}

	srv := dnstest.Start(t, func(dnstest.Query) dnstest.Reply { return dnstest.Refused })
	if res := WalkNSEC(context.Background(), srv.Addr, "example.test", WalkOptions{Timeout: 5 * time.Second}); res.Stop == "" || res.Queries != 1 {
		t.Errorf("refused: %+v, want one query and a stop", res)
	}
}

// TestWalkNSECRate covers #437: every query takes a slot of the limiter.
func TestWalkNSECRate(t *testing.T) {
	t.Parallel()
	srv, _ := chainServer(t, testChain, nil)
	l := NewRateLimiter(1000)
	res := WalkNSEC(context.Background(), srv.Addr, "example.test", WalkOptions{Timeout: 5 * time.Second, Limiter: l})
	if res.Stop != "" || l.reserved != res.Queries {
		t.Errorf("walk %+v took %d limiter slots, want one per query", res, l.reserved)
	}
}

// TestWalkNSECSkip covers #437 and -exclude: names Skip rules out are not
// listed, and no query is sent below an excluded subtree; the walk steps past
// it with corp\000.example.test and goes on to www.
func TestWalkNSECSkip(t *testing.T) {
	t.Parallel()
	srv, asked := chainServer(t, testChain, nil)
	skip := func(name string) bool {
		return strings.HasSuffix(name, ".corp.example.test") || name == "api.example.test"
	}
	res := WalkNSEC(context.Background(), srv.Addr, "example.test", WalkOptions{Timeout: 5 * time.Second, Skip: skip})
	if want := []string{"corp", "www"}; !slices.Equal(res.Names, want) || res.Stop != "" {
		t.Errorf("walk = %+v, want names %v and no stop", res, want)
	}
	for _, q := range asked() {
		if skip(q) {
			t.Errorf("queried %q, which is out of scope", q)
		}
	}
	if q := asked(); !slices.Contains(q, "corp\x00.example.test") {
		t.Errorf("queries %q lack the step past corp", q)
	}

	// Nothing in scope to ask: the walk stops without a query.
	all := func(name string) bool { return name != "example.test" }
	if res := WalkNSEC(context.Background(), srv.Addr, "example.test", WalkOptions{Timeout: 5 * time.Second, Skip: all}); res.Queries != 0 || !strings.Contains(res.Stop, "out of scope") {
		t.Errorf("all excluded: %+v", res)
	}
}

// TestCanonicalCompare checks RFC 4034's order, which the walk's loop guard
// relies on.
func TestCanonicalCompare(t *testing.T) {
	t.Parallel()
	if !slices.IsSortedFunc(testChain, canonicalCompare) {
		t.Errorf("testChain is not in canonical order")
	}
	ordered := []string{"example", "a.example", "yljkjljk.a.example", "z.a.example", "zabc.a.example", "z.example", "\x01.z.example", "*.z.example", "\x00.zabc.example"}
	for i := range ordered {
		for j := range ordered {
			got := canonicalCompare(ordered[i], ordered[j])
			if (i < j && got >= 0) || (i > j && got <= 0) || (i == j && got != 0) {
				t.Errorf("compare(%q, %q) = %d", ordered[i], ordered[j], got)
			}
		}
	}
}
