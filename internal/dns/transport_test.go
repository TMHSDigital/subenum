package dns

import (
	"context"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// startAllTransports serves one zone over UDP/TCP, DoT and DoH and returns
// the -dns-server value for each transport.
func startAllTransports(t *testing.T) (*dnstest.Server, map[string]string) {
	t.Helper()
	h := func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "www.example.com":
			return dnstest.Reply{A: []string{"192.0.2.1"}, AAAA: []string{"2001:db8::1"}}
		case "refused.example.com":
			return dnstest.Refused
		case "dropped.example.com":
			return dnstest.Dropped
		}
		return dnstest.NXDomain
	}
	srv := dnstest.Start(t, h)
	srv.StartTLS(t, h)
	doh := httptest.NewUnstartedServer(srv.DoHHandler(h))
	doh.EnableHTTP2 = true
	doh.StartTLS()
	t.Cleanup(doh.Close)

	pool := srv.RootCAs.Clone()
	pool.AddCert(doh.Certificate())
	old := testRootCAs
	testRootCAs = pool
	t.Cleanup(func() { testRootCAs = old })

	return srv, map[string]string{
		TransportUDP:   srv.Addr,
		TransportTLS:   "tls://" + srv.TLSAddr,
		TransportHTTPS: doh.URL + "/dns-query",
	}
}

// TestTransportsAgree is #86's done-when: lookups through DoT and DoH return
// the same records and outcomes as UDP, with identical per-query accounting.
func TestTransportsAgree(t *testing.T) {
	srv, servers := startAllTransports(t)
	types := []string{"A", "AAAA", "CNAME"}

	var want []Record
	var wantCharged int64
	for _, transport := range []string{TransportUDP, TransportTLS, TransportHTTPS} {
		t.Run(transport, func(t *testing.T) {
			server := servers[transport]
			if got := Transport(server); got != transport {
				t.Fatalf("Transport(%q) = %q", server, got)
			}
			r := NewResolver(2*time.Second, server)
			lim := NewRateLimiter(1_000_000)
			ctx := WithLimiter(context.Background(), lim)

			before := srv.Queries()
			recs, _, err := ResolveTypes(ctx, r, "www.example.com", 2*time.Second, types)
			if err != nil {
				t.Fatalf("www: %v", err)
			}
			wire := srv.Queries() - before
			lim.mu.Lock()
			charged := lim.reserved
			lim.mu.Unlock()
			if wire != charged {
				t.Errorf("wire queries %d, charged %d; want equal", wire, charged)
			}
			if want == nil {
				want, wantCharged = recs, charged
			} else {
				if !slices.Equal(recs, want) {
					t.Errorf("records %v, want %v (as over UDP)", recs, want)
				}
				if charged != wantCharged {
					t.Errorf("charged %d slots, UDP charged %d", charged, wantCharged)
				}
			}

			if _, o := ResolveDomainWithRetry(context.Background(), r, "missing.example.com", 2*time.Second, nil, 2, []string{"A"}); o != OutcomeNXDomain {
				t.Errorf("missing name: outcome %v, want NXDOMAIN", o)
			}
			if _, _, err := ResolveTypes(context.Background(), r, "refused.example.com", 2*time.Second, []string{"A"}); Classify(err) != OutcomeRefused {
				t.Errorf("REFUSED: Classify(%v) = %v, want refused", err, Classify(err))
			}
			short := NewResolver(300*time.Millisecond, server)
			if _, o := ResolveDomainWithRetry(context.Background(), short, "dropped.example.com", 300*time.Millisecond, nil, 1, []string{"A"}); o != OutcomeTimeout {
				t.Errorf("dropped query: outcome %v, want timeout", o)
			}
		})
	}
}

// TestDoTReusesConnections: sequential DoT lookups share pooled connections
// instead of paying a TLS handshake per query.
func TestDoTReusesConnections(t *testing.T) {
	srv, servers := startAllTransports(t)
	r := NewResolver(2*time.Second, servers[TransportTLS])
	before := srv.Connections()
	for i := 0; i < 20; i++ {
		if _, _, err := ResolveTypes(context.Background(), r, "www.example.com", 2*time.Second, []string{"A"}); err != nil {
			t.Fatal(err)
		}
	}
	if opened := srv.Connections() - before; opened > 3 {
		t.Fatalf("20 DoT queries opened %d connections; want them reused", opened)
	}
	if n := srv.QueriesFor("www.example.com", dnsmessage.TypeA); n != 20 {
		t.Fatalf("server saw %d A queries, want 20", n)
	}
}
