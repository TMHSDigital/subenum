package dns

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// TestNoDataIsDefinitiveNegative (#67): NOERROR with no records and an SOA
// (NODATA) is a definitive negative, never retried, and not a failure.
func TestNoDataIsDefinitiveNegative(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.Name == "v4only.example.com" && q.Type == dnsmessage.TypeA {
			return dnstest.Reply{A: []string{"192.0.2.1"}}
		}
		if q.Name == "v4only.example.com" {
			return dnstest.Reply{} // NODATA
		}
		return dnstest.NXDomain
	})
	r := NewResolver(time.Second, srv.Addr)
	recs, outcome := ResolveDomainWithRetry(context.Background(), r, "v4only.example.com", time.Second, nil, 3, []string{"AAAA"})
	if len(recs) != 0 || outcome != OutcomeNXDomain {
		t.Fatalf("AAAA on an A-only name: records %v, outcome %v; want none, NXDOMAIN", recs, outcome)
	}
	if n := srv.QueriesFor("v4only.example.com", dnsmessage.TypeAAAA); n != 1 {
		t.Fatalf("AAAA queries = %d, want 1 (NODATA must not be retried)", n)
	}
	// With A requested too, the name resolves despite the AAAA NODATA.
	recs, outcome = ResolveDomainWithRetry(context.Background(), r, "v4only.example.com", time.Second, nil, 1, DefaultTypes)
	if outcome != OutcomeFound || len(recs) != 1 || recs[0].Value != "192.0.2.1" {
		t.Fatalf("A+AAAA: records %v, outcome %v", recs, outcome)
	}
}

// TestResolverAtIPv6Address (#67): -dns-server can be an IPv6 address.
func TestResolverAtIPv6Address(t *testing.T) {
	srv := dnstest.StartWith(t, dnstest.Options{IPv6: true}, func(q dnstest.Query) dnstest.Reply {
		if q.Name == "www.example.com" && q.Type == dnsmessage.TypeA {
			return dnstest.Reply{A: []string{"192.0.2.7"}}
		}
		return dnstest.Reply{}
	})
	if srv.Addr[0] != '[' {
		t.Fatalf("server address %q is not an IPv6 host:port", srv.Addr)
	}
	recs, outcome := ResolveDomainWithRetry(context.Background(), NewResolver(time.Second, srv.Addr), "www.example.com", time.Second, nil, 1, []string{"A"})
	if outcome != OutcomeFound || len(recs) != 1 {
		t.Fatalf("lookup via %s: records %v, outcome %v", srv.Addr, recs, outcome)
	}
}

// TestWireQueriesPerType (#67) pins the exact queries each record type puts on
// the wire, which -rate's up-front reservation (queriesPerType) relies on.
func TestWireQueriesPerType(t *testing.T) {
	srv := dnstest.Start(t, func(dnstest.Query) dnstest.Reply {
		return dnstest.Reply{A: []string{"192.0.2.1"}, AAAA: []string{"2001:db8::1"}}
	})
	r := NewResolver(time.Second, srv.Addr)
	for _, typ := range []string{"A", "AAAA", "CNAME"} {
		name := "q-" + typ + ".example.com"
		if _, _, err := ResolveTypes(context.Background(), r, name, time.Second, []string{typ}); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		got := map[string]int64{
			"A":     srv.QueriesFor(name, dnsmessage.TypeA),
			"AAAA":  srv.QueriesFor(name, dnsmessage.TypeAAAA),
			"CNAME": srv.QueriesFor(name, dnsmessage.TypeCNAME),
		}
		total := got["A"] + got["AAAA"] + got["CNAME"]
		if int32(total) != queriesPerType[typ] {
			t.Errorf("-type %s sent %v (%d queries); queriesPerType reserves %d", typ, got, total, queriesPerType[typ])
		}
	}
}

// TestTruncationFallsBackToTCP: a truncated UDP answer is retried over TCP,
// and each transport's query is counted.
func TestTruncationFallsBackToTCP(t *testing.T) {
	var sawTCP atomic.Bool
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.TCP {
			sawTCP.Store(true)
		}
		return dnstest.Reply{A: []string{"192.0.2.9"}, Truncate: true}
	})
	recs, _, err := ResolveTypes(context.Background(), NewResolver(time.Second, srv.Addr), "big.example.com", time.Second, []string{"A"})
	if err != nil || len(recs) != 1 || !sawTCP.Load() {
		t.Fatalf("records %v, err %v, TCP retry %v", recs, err, sawTCP.Load())
	}
	if n := srv.QueriesFor("big.example.com", dnsmessage.TypeA); n != 2 {
		t.Fatalf("A queries = %d, want 2 (UDP, then TCP)", n)
	}
}
