package labzone

import (
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"golang.org/x/net/dns/dnsmessage"
)

// TestTransferDirective covers #434: $TRANSFER allow makes a transfer of
// the scanned domain list every defined name except the apex, wildcards
// and failing names; refuse, the default and a transfer of a name below
// the apex are refused; a bad argument is an error.
func TestTransferDirective(t *testing.T) {
	const body = "@ A 192.0.2.1\nwww A 192.0.2.10\nvpn.corp A 192.0.2.30\n*.dev A 192.0.2.99\nslow TIMEOUT\n"
	axfr := func(z *Zone, name string) dnsserver.Reply {
		return z.Handler([]string{"lab.example"})(dnsserver.Query{Name: name, Type: dnsmessage.TypeAXFR, TCP: true})
	}

	z := mustParse(t, "$TRANSFER allow\n"+body)
	if !z.Transfer {
		t.Fatal("$TRANSFER allow did not set Transfer")
	}
	want := []string{"vpn.corp.lab.example", "www.lab.example"}
	if got := axfr(z, "lab.example").Transfer; !slices.Equal(got, want) {
		t.Errorf("transfer gave %v, want %v", got, want)
	}
	if r := axfr(z, "corp.lab.example"); r.RCode != dnsmessage.RCodeRefused {
		t.Errorf("transfer below the apex: %+v, want REFUSED", r)
	}
	// Other queries are answered as before.
	if r := z.Handler([]string{"lab.example"})(dnsserver.Query{Name: "www.lab.example", Type: dnsmessage.TypeA}); !slices.Equal(r.A, []string{"192.0.2.10"}) {
		t.Errorf("A query: %+v", r)
	}

	for _, s := range []string{body, "$TRANSFER refuse\n" + body} {
		if r := axfr(mustParse(t, s), "lab.example"); r.RCode != dnsmessage.RCodeRefused || r.Transfer != nil {
			t.Errorf("%q: %+v, want REFUSED", strings.SplitN(s, "\n", 2)[0], r)
		}
	}
	if _, err := Parse(strings.NewReader("$TRANSFER maybe\n")); err == nil || !strings.Contains(err.Error(), "allow or refuse") {
		t.Errorf("bad argument: %v", err)
	}
}
