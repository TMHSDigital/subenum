package dns

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// TestAskDelegation covers #406: a non-recursive NS query to the parent
// zone's server returns the delegation's name servers, from a referral's
// authority section or from the answer section, and an error RCODE is an
// error. The query does not ask for recursion.
func TestAskDelegation(t *testing.T) {
	var recursive atomic.Bool
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.Recursive {
			recursive.Store(true)
		}
		switch q.Name {
		case "old.example.test":
			return dnstest.Reply{Referral: []string{"NS1.gone.example.", "ns2.gone.example", "ns1.gone.example"}}
		case "deep.old.example.test":
			// A referral for the cut above the name is not the name's own.
			return dnstest.Reply{Referral: []string{"ns1.gone.example"}, ReferralZone: "old.example.test"}
		case "inzone.example.test":
			return dnstest.Reply{NS: []string{"ns1.example.test"}}
		case "www.example.test":
			return dnstest.Reply{}
		case "broken.example.test":
			return dnstest.ServFail
		}
		return dnstest.NXDomain
	})
	for _, c := range []struct {
		name    string
		want    []string
		wantErr string
	}{
		{"Old.Example.Test.", []string{"ns1.gone.example", "ns2.gone.example"}, ""},
		{"deep.old.example.test", nil, ""},
		{"inzone.example.test", []string{"ns1.example.test"}, ""},
		{"www.example.test", nil, ""},
		{"broken.example.test", nil, "ServerFailure"},
		{"missing.example.test", nil, "NameError"},
	} {
		hosts, sent, err := AskDelegation(context.Background(), srv.Addr, c.name, 5*time.Second)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: err = %v, want %s", c.name, err, c.wantErr)
			}
		} else if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if !slices.Equal(hosts, c.want) || sent != 1 {
			t.Errorf("%s: hosts %v (%d queries), want %v (1)", c.name, hosts, sent, c.want)
		}
	}
	if srv.QueriesFor("old.example.test", dnsmessage.TypeNS) != 1 {
		t.Error("the delegation was not asked with an NS query")
	}
	if recursive.Load() {
		t.Error("a delegation query asked for recursion")
	}
}

// TestAskDelegationPacedAndCounted covers #406: each query takes a slot of
// the rate limiter on ctx and is counted by its query counter, the TCP retry
// of a truncated answer included.
func TestAskDelegationPacedAndCounted(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		return dnstest.Reply{Referral: []string{"ns1.gone.example"}, Truncate: !q.TCP}
	})
	lim := NewRateLimiter(1000)
	var counted atomic.Int64
	ctx := WithQueryCounter(WithLimiter(context.Background(), lim), &counted)
	hosts, sent, err := AskDelegation(ctx, srv.Addr, "old.example.test", 5*time.Second)
	if err != nil || !slices.Equal(hosts, []string{"ns1.gone.example"}) {
		t.Fatalf("hosts %v, err %v", hosts, err)
	}
	lim.mu.Lock()
	reserved := lim.reserved
	lim.mu.Unlock()
	if sent != 2 || counted.Load() != 2 || reserved != 2 {
		t.Errorf("sent %d, counted %d, rate slots %d; want 2 each (UDP, then TCP)", sent, counted.Load(), reserved)
	}
}
