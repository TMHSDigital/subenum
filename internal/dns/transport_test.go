package dns

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
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
	dnstest.StartTLS(t, srv, h)
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

// TestDoTDiscardsClosedConnections covers #113: a server that closes each
// connection after one answer costs one dial per query, not two, because a
// pooled connection the server closed is detected before it is reused.
func TestDoTDiscardsClosedConnections(t *testing.T) {
	srv, servers := startAllTransports(t)
	srv.CloseStreamsAfter(1)
	r := NewResolver(2*time.Second, servers[TransportTLS])
	var sent atomic.Int64
	ctx := WithQueryCounter(context.Background(), &sent)
	before := srv.Connections()
	for i := 0; i < 10; i++ {
		if _, _, err := ResolveTypes(ctx, r, "www.example.com", 2*time.Second, []string{"A"}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond) // let the server's close arrive
	}
	if opened := srv.Connections() - before; opened != 10 {
		t.Errorf("10 lookups opened %d connections, want 10", opened)
	}
	if sent.Load() != 10 {
		t.Errorf("counted %d queries, want 10", sent.Load())
	}
}

// TestCloseIdleConnections: a scan's DoT connections are closed when it
// ends, and the resolver still works afterwards.
func TestCloseIdleConnections(t *testing.T) {
	srv, servers := startAllTransports(t)
	r := NewResolver(2*time.Second, servers[TransportTLS])
	if _, _, err := ResolveTypes(context.Background(), r, "www.example.com", 2*time.Second, []string{"A"}); err != nil {
		t.Fatal(err)
	}
	CloseIdleConnections(r)
	before := srv.Connections()
	if _, _, err := ResolveTypes(context.Background(), r, "www.example.com", 2*time.Second, []string{"A"}); err != nil {
		t.Fatal(err)
	}
	if srv.Connections() == before {
		t.Error("the lookup after CloseIdleConnections reused a connection that should have been closed")
	}
}

// TestDoHRefusesRedirects covers #114: a DoH server that redirects, even to
// plain http://, never gets the query sent there.
func TestDoHRefusesRedirects(t *testing.T) {
	var plainHits atomic.Int64
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { plainHits.Add(1) }))
	defer plain.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/dns-query", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	trustOnly(t, redirect)

	r := NewResolver(2*time.Second, redirect.URL+"/dns-query")
	if _, _, err := ResolveTypes(context.Background(), r, "www.example.com", 2*time.Second, []string{"A"}); err == nil {
		t.Fatal("lookup through a redirecting server succeeded")
	}
	if plainHits.Load() != 0 {
		t.Errorf("the query was sent in cleartext %d times", plainHits.Load())
	}
}

// TestDoHThrottlingIsRefused covers #114: HTTP 429 and 503 count as
// REFUSED, the rate-limit signal, not as "other".
func TestDoHThrottlingIsRefused(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		trustOnly(t, srv)
		r := NewResolver(2*time.Second, srv.URL+"/dns-query")
		_, _, err := ResolveTypes(context.Background(), r, "www.example.com", 2*time.Second, []string{"A"})
		srv.Close()
		if outcome := Classify(err); outcome != OutcomeRefused {
			t.Errorf("HTTP %d: outcome %v, want refused", status, outcome)
		}
	}
}

// TestDoTRejectsUntrustedCertificate: certificate verification is on, so a
// server whose certificate is not trusted never answers a lookup.
func TestDoTRejectsUntrustedCertificate(t *testing.T) {
	_, servers := startAllTransports(t)
	testRootCAs = x509.NewCertPool() // trusts nothing; startAllTransports restores it
	r := NewResolver(2*time.Second, servers[TransportTLS])
	if _, _, err := ResolveTypes(context.Background(), r, "www.example.com", 2*time.Second, []string{"A"}); err == nil {
		t.Fatal("lookup over an untrusted DoT certificate succeeded")
	}
}

// trustOnly makes DoT and DoH trust srv's certificate for this test.
func trustOnly(t *testing.T, srv *httptest.Server) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	old := testRootCAs
	testRootCAs = pool
	t.Cleanup(func() { testRootCAs = old })
}
