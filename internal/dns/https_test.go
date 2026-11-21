package dns

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"golang.org/x/net/dns/dnsmessage"
)

// httpsZone answers the HTTPS tests: an AliasMode name, a ServiceMode name
// with two records, an alias of it, a name with only an address (NODATA
// for HTTPS), takeover targets, and NXDOMAIN for the rest.
func httpsZone(q dnstest.Query) dnstest.Reply {
	switch q.Name {
	case "alias.example.com":
		return dnstest.Reply{HTTPS: []string{"0 Edge.Example.NET."}}
	case "svc.example.com":
		return dnstest.Reply{A: []string{"192.0.2.1"}, HTTPS: []string{"2 Alt.example.com alpn=h2 port=8443", "1 . alpn=h2,h3 port=443"}}
	case "www.example.com":
		return dnstest.Reply{CNAME: "svc.example.com", A: []string{"192.0.2.1"}, HTTPS: []string{"1 . alpn=h2,h3 port=443", "2 Alt.example.com alpn=h2 port=8443"}}
	case "plain.example.com", "acme.github.io", "edge.example.net":
		return dnstest.Reply{A: []string{"192.0.2.2"}}
	case "pages.example.com":
		return dnstest.Reply{HTTPS: []string{"0 acme.github.io"}}
	case "gone.example.com":
		return dnstest.Reply{HTTPS: []string{"0 deleted.example.net"}}
	case "svcgone.example.com":
		return dnstest.Reply{HTTPS: []string{"1 deleted.example.net alpn=h2"}}
	case "both.example.com":
		return dnstest.Reply{CNAME: "edge.example.net", HTTPS: []string{"0 acme.github.io"}}
	}
	return dnstest.NXDomain
}

// TestResolveHTTPS covers #438: -type HTTPS reads AliasMode and ServiceMode
// records as "<priority> <target> [alpn=...] [port=...]", sorted, follows an
// alias to the records of its target, sends one query a lookup, and treats
// NODATA and NXDOMAIN as negatives.
func TestResolveHTTPS(t *testing.T) {
	srv := dnstest.Start(t, httpsZone)
	l := Lookup{Resolver: NewResolver(time.Second, srv.Addr), Timeout: time.Second, Attempts: 1, Types: []string{"HTTPS"}}
	svc := []Record{{Type: "HTTPS", Value: "1 . alpn=h2,h3 port=443"}, {Type: "HTTPS", Value: "2 alt.example.com alpn=h2 port=8443"}}
	for name, want := range map[string][]Record{
		"alias.example.com": {{Type: "HTTPS", Value: "0 edge.example.net"}},
		"svc.example.com":   svc,
		"www.example.com":   svc,
	} {
		var queries atomic.Int64
		recs, outcome := l.Resolve(WithQueryCounter(context.Background(), &queries), name)
		if outcome != OutcomeFound || !slices.Equal(recs, want) {
			t.Errorf("%s = %v %v, want %v", name, recs, outcome, want)
		}
		if n := queries.Load(); n != 1 {
			t.Errorf("%s: %d queries, want 1", name, n)
		}
	}
	for _, name := range []string{"plain.example.com", "missing.example.com"} {
		if recs, outcome := l.Resolve(context.Background(), name); outcome != OutcomeNXDomain {
			t.Errorf("%s = %v %v, want a negative", name, recs, outcome)
		}
	}
	// A name with an address but no HTTPS record is still found by A.
	l.Types = []string{"A", "HTTPS"}
	if recs, outcome := l.Resolve(context.Background(), "plain.example.com"); outcome != OutcomeFound || len(recs) != 1 || recs[0].Type != "A" {
		t.Errorf("plain.example.com with A,HTTPS = %v %v", recs, outcome)
	}
}

// TestHTTPSTypeCost covers #438: HTTPS is a -type value of one query, and
// not one of the default types.
func TestHTTPSTypeCost(t *testing.T) {
	types, err := ParseTypes("a,https")
	if err != nil || !slices.Equal(types, []string{"A", "HTTPS"}) {
		t.Fatalf("ParseTypes(a,https) = %v, %v", types, err)
	}
	if n := QueriesFor(types); n != 2 {
		t.Errorf("QueriesFor(A,HTTPS) = %d, want 2", n)
	}
	if slices.Contains(DefaultTypes, "HTTPS") {
		t.Error("HTTPS is a default type")
	}
	if !HintsTakeover([]string{"HTTPS"}) {
		t.Error("HintsTakeover(HTTPS) = false")
	}
}

// TestFormatHTTPS covers #438: AliasMode parameters are ignored, a
// malformed alpn or port is left out, and the bytes of an alpn ID, which
// the scanned zone's owner writes, are escaped so the list reads back
// unambiguously.
func TestFormatHTTPS(t *testing.T) {
	dot := dnsmessage.MustNewName(".")
	host := dnsmessage.MustNewName("Alt.Example.com.")
	rec := func(prio uint16, target dnsmessage.Name, params ...dnsmessage.SVCParam) dnsmessage.SVCBResource {
		return dnsmessage.SVCBResource{Priority: prio, Target: target, Params: params}
	}
	alpn := func(b ...byte) dnsmessage.SVCParam {
		return dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: b}
	}
	port := func(b ...byte) dnsmessage.SVCParam {
		return dnsmessage.SVCParam{Key: dnsmessage.SVCParamPort, Value: b}
	}
	for _, tc := range []struct {
		rec  dnsmessage.SVCBResource
		want string
	}{
		{rec(0, host, alpn(2, 'h', '2')), "0 alt.example.com"},
		{rec(0, dot), "0 ."},
		{rec(1, dot, alpn(2, 'h', '2', 2, 'h', '3'), port(1, 187)), "1 . alpn=h2,h3 port=443"},
		{rec(3, host, alpn(5, 'a', ',', 'b', ' ', '\n')), `3 alt.example.com alpn=a\044b\032\010`},
		{rec(1, dot, alpn(9, 'h'), port(1)), "1 ."},
		{rec(1, dot, alpn()), "1 ."},
	} {
		if got, ok := formatHTTPS(tc.rec); !ok || got != tc.want {
			t.Errorf("formatHTTPS(%#v) = %q %v, want %q", tc.rec, got, ok, tc.want)
		}
	}
	bad := dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.Name{Data: [255]byte{'a', '\x1b', '.'}, Length: 3}}
	if got, ok := formatHTTPS(bad); ok {
		t.Errorf("formatHTTPS with a control byte in the target = %q, want refused", got)
	}
}

// TestTakeoverHintHTTPSAlias covers #438: an AliasMode HTTPS target is
// checked like a CNAME target (a takeover-prone provider, a target that
// does not exist), a ServiceMode target is not, and a CNAME wins over an
// alias.
func TestTakeoverHintHTTPSAlias(t *testing.T) {
	srv := dnstest.Start(t, httpsZone)
	r := NewResolver(time.Second, srv.Addr)
	for name, want := range map[string]string{
		"pages.example.com":   "provider:github-pages",
		"gone.example.com":    "dangling",
		"alias.example.com":   "",
		"svcgone.example.com": "",
		"both.example.com":    "",
	} {
		t.Run(name, func(t *testing.T) {
			recs, _, _ := Lookup{Resolver: r, Timeout: time.Second, Types: []string{"CNAME", "HTTPS"}}.ResolveTypes(context.Background(), name)
			if got := TakeoverHint(context.Background(), Lookup{Resolver: r, Timeout: time.Second, Attempts: 1}, recs); got != want {
				t.Errorf("TakeoverHint(%v) = %q, want %q", recs, got, want)
			}
		})
	}
}
