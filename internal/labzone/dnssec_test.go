package labzone

import (
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"golang.org/x/net/dns/dnsmessage"
)

// TestDNSSECDirective covers #437: $DNSSEC nsec makes the answer for a name
// that owns no record carry the NSEC record covering it, from a chain of the
// apex, the defined names (not failing ones) and the wildcards in canonical
// order, the last leading back to the apex. A name that owns records gets
// none. nsec3 adds an NSEC3 record instead; none, the default, adds nothing.
func TestDNSSECDirective(t *testing.T) {
	const body = "www A 192.0.2.10\nvpn.corp A 192.0.2.30\n*.dev A 192.0.2.99\nslow TIMEOUT\n"
	ask := func(z *Zone, name string) dnsserver.Reply {
		return z.Handler([]string{"lab.example"})(dnsserver.Query{Name: name, Type: dnsmessage.TypeA})
	}
	z := mustParse(t, "$DNSSEC nsec\n"+body)
	if z.DNSSEC != "nsec" {
		t.Fatalf("DNSSEC = %q", z.DNSSEC)
	}
	for name, want := range map[string]dnsserver.NSEC{
		"\x00.lab.example":          {Owner: "lab.example", Next: "vpn.corp.lab.example"},
		"corp.lab.example":          {Owner: "lab.example", Next: "vpn.corp.lab.example"}, // an ancestor only: NODATA
		"\x00.vpn.corp.lab.example": {Owner: "vpn.corp.lab.example", Next: "*.dev.lab.example"},
		"x.dev.lab.example":         {Owner: "*.dev.lab.example", Next: "www.lab.example"}, // the wildcard's answer
		"zzz.lab.example":           {Owner: "www.lab.example", Next: "lab.example"},
	} {
		if r := ask(z, name); !slices.Equal(r.NSEC, []dnsserver.NSEC{want}) {
			t.Errorf("%q: NSEC %+v, want %+v", name, r.NSEC, want)
		}
	}
	for _, name := range []string{"www.lab.example", "lab.example"} {
		if r := ask(z, name); r.NSEC != nil || r.Denial != "" {
			t.Errorf("%q owns records but got %+v", name, r)
		}
	}
	if r := ask(z, "slow.lab.example"); !r.Drop || r.NSEC != nil {
		t.Errorf("a TIMEOUT name: %+v", r)
	}

	if r := ask(mustParse(t, "$DNSSEC nsec3\n"+body), "zzz.lab.example"); r.Denial != "nsec3" || r.NSEC != nil {
		t.Errorf("nsec3: %+v", r)
	}
	for _, s := range []string{body, "$DNSSEC none\n" + body} {
		if r := ask(mustParse(t, s), "zzz.lab.example"); r.Denial != "" || r.NSEC != nil {
			t.Errorf("%q: %+v, want no proof", strings.SplitN(s, "\n", 2)[0], r)
		}
	}
	if _, err := Parse(strings.NewReader("$DNSSEC yes\n")); err == nil || !strings.Contains(err.Error(), "nsec, nsec3 or none") {
		t.Errorf("bad argument: %v", err)
	}
}
