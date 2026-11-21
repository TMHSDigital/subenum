package labzone

import (
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"golang.org/x/net/dns/dnsmessage"
)

// TestPTRRecords covers #436: "<address> PTR <host>" answers the address's
// reverse name, a relative host under the scanned domain; other reverse
// names are NXDOMAIN; a bad owner or host is an error.
func TestPTRRecords(t *testing.T) {
	z := mustParse(t, "www A 192.0.2.10\n192.0.2.10 PTR host-12.dc1\n192.0.2.10 PTR mail.example.net.\n2001:db8::1 PTR v6\n")
	h := z.Handler([]string{"lab.example"})
	ask := func(name string, typ dnsmessage.Type) dnsserver.Reply {
		return h(dnsserver.Query{Name: name, Type: typ})
	}
	if r := ask("10.2.0.192.in-addr.arpa", dnsmessage.TypePTR); !slices.Equal(r.PTR, []string{"host-12.dc1.lab.example", "mail.example.net"}) {
		t.Errorf("IPv4 PTR: %+v", r)
	}
	if r := ask("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", dnsmessage.TypePTR); !slices.Equal(r.PTR, []string{"v6.lab.example"}) {
		t.Errorf("IPv6 PTR: %+v", r)
	}
	if r := ask("11.2.0.192.in-addr.arpa", dnsmessage.TypePTR); r.RCode != dnsmessage.RCodeNameError {
		t.Errorf("address without a PTR record: %+v, want NXDOMAIN", r)
	}
	if r := ask("www.lab.example", dnsmessage.TypeA); !slices.Equal(r.A, []string{"192.0.2.10"}) {
		t.Errorf("A query: %+v", r)
	}
	for _, bad := range []string{"www PTR host\n", "192.0.2.10 PTR\n", "192.0.2.10 PTR @\n"} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
