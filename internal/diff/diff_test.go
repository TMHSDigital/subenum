package diff

import (
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// TestRecordsChanged covers #189's comparison rule.
func TestRecordsChanged(t *testing.T) {
	a := func(v string) dns.Record { return dns.Record{Type: "A", Value: v} }
	cname := func(v string) dns.Record { return dns.Record{Type: "CNAME", Value: v} }
	all := []string{"A", "AAAA", "CNAME"}
	for _, c := range []struct {
		name      string
		prev, cur []dns.Record
		types     []string
		want      bool
	}{
		{"same addresses in another order", []dns.Record{a("192.0.2.1"), a("192.0.2.2")}, []dns.Record{a("192.0.2.2"), a("192.0.2.1")}, all, false},
		{"moved address", []dns.Record{a("192.0.2.1")}, []dns.Record{a("192.0.2.9")}, all, true},
		{"extra address", []dns.Record{a("192.0.2.1")}, []dns.Record{a("192.0.2.1"), a("192.0.2.2")}, all, true},
		{"re-pointed alias", []dns.Record{cname("app.cdn.example")}, []dns.Record{cname("unclaimed.example")}, all, true},
		{"CDN addresses rotate behind a stable alias", []dns.Record{cname("app.cdn.example"), a("192.0.2.1")}, []dns.Record{cname("app.cdn.example"), a("192.0.2.7")}, all, false},
		{"alias case and trailing dot", []dns.Record{cname("App.CDN.example.")}, []dns.Record{cname("app.cdn.example")}, all, false},
		{"address became an alias", []dns.Record{a("192.0.2.1")}, []dns.Record{cname("x.example"), a("192.0.2.1")}, all, true},
		{"types this run did not look up are ignored", []dns.Record{a("192.0.2.1"), {Type: "AAAA", Value: "2001:db8::1"}}, []dns.Record{a("192.0.2.1")}, []string{"A"}, false},
		{"without CNAME lookups addresses decide", []dns.Record{cname("x.example"), a("192.0.2.1")}, []dns.Record{a("192.0.2.1")}, []string{"A", "AAAA"}, false},
		{"no types compares every type", []dns.Record{a("192.0.2.1"), {Type: "TXT", Value: "v=spf1 -all"}}, []dns.Record{a("192.0.2.1")}, nil, true},
		{"no types still prefers the alias", []dns.Record{cname("app.cdn.example"), a("192.0.2.1")}, []dns.Record{cname("app.cdn.example"), a("192.0.2.7")}, nil, false},
	} {
		if got := RecordsChanged(c.prev, c.cur, c.types); got != c.want {
			t.Errorf("%s: changed = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestName(t *testing.T) {
	if got := Name("  WWW.Example.COM. "); got != "www.example.com" {
		t.Fatalf("Name = %q", got)
	}
}
