package dns

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestResolveDomain(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"example.com":     {A: "192.0.2.1"},
		"www.example.com": {A: "192.0.2.2"},
	})
	timeout := time.Second
	r := srv.Resolver(timeout)

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{name: "existing apex", domain: "example.com.", expected: true},
		{name: "existing subdomain", domain: "www.example.com.", expected: true},
		{name: "missing domain", domain: "nope.example.com.", expected: false},
		{name: "empty domain", domain: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveDomain(context.Background(), r, tt.domain, timeout, false)
			if got != tt.expected {
				t.Errorf("ResolveDomain(%q) = %v, want %v", tt.domain, got, tt.expected)
			}
		})
	}
}

func TestResolveDomainTimeout(t *testing.T) {
	addr := startBlackHole(t)
	veryShortTimeout := time.Millisecond
	r := NewResolver(veryShortTimeout, addr)
	if ResolveDomain(context.Background(), r, "example.com.", veryShortTimeout, false) {
		t.Errorf("expected timeout against a black-holed resolver")
	}
}

func TestResolveDomainWithRetry(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"example.com": {A: "192.0.2.1"},
	})
	timeout := time.Second
	r := srv.Resolver(timeout)

	records, result := ResolveDomainWithRetry(context.Background(), r, "example.com.", timeout, false, 3, []string{"A"})
	if result != OutcomeFound {
		t.Errorf("expected example.com to resolve, got %v", result)
	}
	if len(records) == 0 {
		t.Errorf("expected records, got none")
	}

	_, result = ResolveDomainWithRetry(context.Background(), r, "missing.example.com.", timeout, false, 2, []string{"A"})
	if result == OutcomeFound {
		t.Errorf("expected missing name to fail")
	}
}

func TestResolveDomainWithRetryContextCancellation(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{"example.com": {A: "192.0.2.1"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	timeout := time.Second
	start := time.Now()
	_, result := ResolveDomainWithRetry(ctx, srv.Resolver(timeout), "example.com.", timeout, false, 5, []string{"A"})
	elapsed := time.Since(start)

	if result == OutcomeFound {
		t.Errorf("expected cancelled context to prevent resolution")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("expected near-instant return on cancelled context, took %s", elapsed)
	}
}

func TestCheckWildcard(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"www.example.com": {A: "192.0.2.1"},
	})
	timeout := time.Second
	isWildcard, _, err := CheckWildcard(context.Background(), srv.Resolver(timeout), "example.com", timeout, nil)
	if err != nil {
		t.Fatalf("CheckWildcard returned error: %v", err)
	}
	if isWildcard {
		t.Errorf("expected example.com not to be a wildcard")
	}
}

func TestCheckWildcardCancelled(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := CheckWildcard(ctx, srv.Resolver(time.Second), "example.com", time.Second, nil)
	if err == nil {
		t.Errorf("expected error from cancelled context")
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Outcome
	}{
		{name: "nil", err: nil, want: OutcomeFound},
		{
			name: "nxdomain",
			err:  &net.DNSError{Err: "no such host", Name: "missing.example.com", IsNotFound: true},
			want: OutcomeNXDomain,
		},
		{
			name: "timeout",
			err:  &net.DNSError{Err: "i/o timeout", Name: "slow.example.com", IsTimeout: true},
			want: OutcomeTimeout,
		},
		{
			name: "refused",
			err:  &net.DNSError{Err: "server refused", Name: "blocked.example.com"},
			want: OutcomeRefused,
		},
		{
			name: "refused mixed case",
			err:  &net.DNSError{Err: "REFUSED"},
			want: OutcomeRefused,
		},
		{
			name: "other dns error",
			err:  &net.DNSError{Err: "server misbehaving", Name: "x.example.com"},
			want: OutcomeOther,
		},
		{
			name: "generic error",
			err:  fmt.Errorf("dial udp: connection refused"),
			want: OutcomeOther,
		},
		{
			name: "wrapped nxdomain",
			err:  fmt.Errorf("lookup: %w", &net.DNSError{Err: "no such host", IsNotFound: true}),
			want: OutcomeNXDomain,
		},
		{
			name: "context canceled",
			err:  fmt.Errorf("lookup x: %w", context.Canceled),
			want: OutcomeCanceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.err); got != tt.want {
				t.Errorf("Classify() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestResolveDomainWithRetryCNAMENoData covers #28: a name that exists with
// only an A record has no CNAME. That is a definitive negative, not a resolver
// failure, and it must not be retried.
func TestResolveDomainWithRetryCNAMENoData(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{"www.example.com": {A: "192.0.2.10"}})
	records, outcome := ResolveDomainWithRetry(context.Background(), srv.Resolver(time.Second), "www.example.com", time.Second, false, 3, []string{"CNAME"})
	if len(records) != 0 {
		t.Fatalf("records = %v, want none", records)
	}
	if outcome != OutcomeNXDomain {
		t.Fatalf("outcome = %v, want NXDomain (NODATA)", outcome)
	}
	first := srv.Queries()

	// A second identical call with attempts=1 must issue the same number of
	// queries, proving the attempts=3 call above did not retry.
	_, _ = ResolveDomainWithRetry(context.Background(), srv.Resolver(time.Second), "www.example.com", time.Second, false, 1, []string{"CNAME"})
	if got := srv.Queries() - first; got != first {
		t.Fatalf("attempts=3 issued %d queries, attempts=1 issued %d; NODATA must not be retried", first, got)
	}
}

// TestCheckWildcardCNAMEFingerprint covers the second half of #28: with
// -type CNAME the wildcard fingerprint must carry the CNAME target, otherwise
// recordsSubset can never filter CNAME-wildcard answers under -force.
func TestCheckWildcardCNAMEFingerprint(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"*":                {CNAME: "edge.example.net"},
		"edge.example.net": {A: "192.0.2.50"},
	})
	is, fp, err := CheckWildcard(context.Background(), srv.Resolver(time.Second), "example.com", time.Second, []string{"CNAME"})
	if err != nil {
		t.Fatalf("CheckWildcard: %v", err)
	}
	if !is {
		t.Fatal("expected CNAME wildcard to be detected")
	}
	want := Record{Type: "CNAME", Value: "edge.example.net"}
	if len(fp) != 1 || fp[0] != want {
		t.Fatalf("fingerprint = %v, want [%v]", fp, want)
	}

	// A real hit under the same wildcard returns the same CNAME, so it is a
	// subset of the fingerprint and would be filtered.
	recs, _, _ := ResolveTypes(context.Background(), srv.Resolver(time.Second), "www.example.com", time.Second, []string{"CNAME"})
	if len(recs) != 1 || recs[0] != want {
		t.Fatalf("www CNAME records = %v, want [%v]", recs, want)
	}
}

func TestResolveDomainWithRetryCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, outcome := ResolveDomainWithRetry(ctx, NewResolver(time.Second, startBlackHole(t)), "x.example.com", time.Second, false, 3, nil)
	if outcome != OutcomeCanceled {
		t.Fatalf("outcome = %v, want Canceled", outcome)
	}
}

func TestResolveDomainWithRetryNXDomainNoRetry(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{})
	_, outcome := ResolveDomainWithRetry(context.Background(), srv.Resolver(time.Second), "nope.example.com.", time.Second, false, 3, []string{"A"})
	if outcome != OutcomeNXDomain {
		t.Fatalf("outcome = %v, want NXDomain", outcome)
	}
	if got := srv.Queries(); got != 1 {
		t.Fatalf("queries = %d, want 1 (NXDOMAIN must not be retried)", got)
	}
}

func TestCheckWildcardFingerprint(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"*": {A: "192.0.2.99"},
	})
	is, fp, err := CheckWildcard(context.Background(), srv.Resolver(time.Second), "example.com", time.Second, nil)
	if err != nil {
		t.Fatalf("CheckWildcard: %v", err)
	}
	if !is {
		t.Fatal("expected wildcard")
	}
	foundIP := false
	for _, r := range fp {
		if r.Type == "A" && r.Value == "192.0.2.99" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("fingerprint %v missing A 192.0.2.99", fp)
	}
}

func TestResolveTypesTCPFallbackOnTruncation(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{
		"big.example.com": {A: "192.0.2.1", Truncated: true},
	})
	recs, _, err := ResolveTypes(context.Background(), srv.Resolver(2*time.Second), "big.example.com.", 2*time.Second, []string{"A"})
	if err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}
	if len(recs) != 1 || recs[0].Type != "A" || recs[0].Value != "192.0.2.1" {
		t.Fatalf("records = %v, want A 192.0.2.1", recs)
	}
	if srv.Queries() < 2 {
		t.Fatalf("queries = %d, want UDP then TCP", srv.Queries())
	}
}

func TestLiveResolverSmoke(t *testing.T) {
	if os.Getenv("SUBENUM_NETWORK_TESTS") != "1" {
		t.Skip("set SUBENUM_NETWORK_TESTS=1 to enable live resolver smoke test")
	}
	timeout := 3 * time.Second
	r := NewResolver(timeout, "8.8.8.8:53")
	if !ResolveDomain(context.Background(), r, "example.com.", timeout, false) {
		t.Fatal("expected example.com to resolve via 8.8.8.8")
	}
}

func TestResolveTypesAAAA(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{"v6.example.com": {A: "192.0.2.1", AAAA: "2001:db8::1"}})
	recs, _, err := ResolveTypes(context.Background(), srv.Resolver(time.Second), "v6.example.com", time.Second, DefaultTypes)
	if err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}
	want := []Record{{Type: "A", Value: "192.0.2.1"}, {Type: "AAAA", Value: "2001:db8::1"}}
	if len(recs) != 2 || recs[0] != want[0] || recs[1] != want[1] {
		t.Fatalf("records = %v, want %v", recs, want)
	}
}

// TestResolveTypesServFailOutranksNXDomain covers #31: SERVFAIL on A followed
// by NXDOMAIN on AAAA must classify as a failure (and be retried), not as a
// definitive NXDOMAIN.
func TestResolveTypesServFailOutranksNXDomain(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{"flaky.example.com": {ServFailA: true}})
	r := srv.Resolver(time.Second)

	_, outcome := ResolveDomainWithRetry(context.Background(), r, "flaky.example.com", time.Second, false, 1, DefaultTypes)
	if outcome == OutcomeNXDomain {
		t.Fatal("SERVFAIL on A was masked by NXDOMAIN on AAAA")
	}
	if outcome != OutcomeOther {
		t.Fatalf("outcome = %v, want Other (SERVFAIL)", outcome)
	}
	single := srv.Queries()

	_, _ = ResolveDomainWithRetry(context.Background(), r, "flaky.example.com", time.Second, false, 3, DefaultTypes)
	if retried := srv.Queries() - single; retried <= single {
		t.Fatalf("attempts=3 sent %d queries vs %d for attempts=1; the failure was not retried", retried, single)
	}
}

// TestResolveTypesSlowADoesNotStarveAAAA covers ROADMAP N3: each record type has
// its own timeout, so an A answer slower than -timeout cannot use up the AAAA
// lookup's budget.
func TestResolveTypesSlowADoesNotStarveAAAA(t *testing.T) {
	srv := startTestDNS(t, map[string]testReply{"slow.example.com": {A: "192.0.2.1", AAAA: "2001:db8::2", DelayA: 600 * time.Millisecond}})
	timeout := 300 * time.Millisecond
	recs, _, err := ResolveTypes(context.Background(), srv.Resolver(timeout), "slow.example.com", timeout, DefaultTypes)
	if len(recs) != 1 || recs[0] != (Record{Type: "AAAA", Value: "2001:db8::2"}) {
		t.Fatalf("records = %v (err %v), want only the AAAA record", recs, err)
	}
	if Classify(err) != OutcomeTimeout {
		t.Fatalf("err = %v, want the A timeout reported", err)
	}
}
