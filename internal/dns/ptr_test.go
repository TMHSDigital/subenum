package dns

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

func TestReverseName(t *testing.T) {
	t.Parallel()
	for addr, want := range map[string]string{
		"192.0.2.7":        "7.2.0.192.in-addr.arpa",
		"::ffff:192.0.2.7": "7.2.0.192.in-addr.arpa",
		"2001:db8::1":      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
	} {
		if got, err := ReverseName(addr); err != nil || got != want {
			t.Errorf("ReverseName(%s) = %q, %v; want %q", addr, got, err, want)
		}
	}
	if _, err := ReverseName("not-an-ip"); err == nil {
		t.Error("ReverseName accepted a non-address")
	}
}

// TestLookupPTR covers #436: a PTR answer comes back lower case without the
// trailing dot, NXDOMAIN is an error, and each lookup is one counted query
// under the limiter.
func TestLookupPTR(t *testing.T) {
	t.Parallel()
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.Type == dnsmessage.TypePTR && q.Name == "7.2.0.192.in-addr.arpa" {
			return dnstest.Reply{PTR: []string{"Host-12.DC1.example.com"}}
		}
		return dnstest.NXDomain
	})
	l := Lookup{Resolver: NewResolver(2*time.Second, srv.Addr), Timeout: 2 * time.Second}
	var sent atomic.Int64
	ctx := WithQueryCounter(WithLimiter(context.Background(), NewRateLimiter(1000)), &sent)
	names, err := l.LookupPTR(ctx, "192.0.2.7")
	if err != nil || !slices.Equal(names, []string{"host-12.dc1.example.com"}) {
		t.Fatalf("LookupPTR = %v, %v", names, err)
	}
	if _, err := l.LookupPTR(ctx, "192.0.2.8"); Classify(err) != OutcomeNXDomain {
		t.Errorf("no PTR record: err %v, want NXDOMAIN", err)
	}
	if n := sent.Load(); n != 2 {
		t.Errorf("queries counted %d, want 2", n)
	}
}
