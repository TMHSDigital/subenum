package labzone

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"golang.org/x/net/dns/dnsmessage"
)

const scenario = `
# a small lab
$DELAY 5ms
@        A      192.0.2.1
www      A      192.0.2.10
www      AAAA   2001:db8::10
shop     CNAME  www
blog     CNAME  ghost.example.net.
vpn.corp A      192.0.2.30
*.dev    A      192.0.2.99
api.dev  A      192.0.2.40
slow     TIMEOUT
broken   SERVFAIL
`

func mustParse(t *testing.T, s string) *Zone {
	t.Helper()
	z, err := Parse(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func TestAnswer(t *testing.T) {
	z := mustParse(t, scenario)
	const origin = "lab.example"
	cases := []struct {
		rel   string
		rcode dnsmessage.RCode
		a     []string
		cname string
		drop  bool
	}{
		{rel: "", a: []string{"192.0.2.1"}},
		{rel: "www", a: []string{"192.0.2.10"}},
		{rel: "shop", cname: "www.lab.example", a: []string{"192.0.2.10"}},
		{rel: "blog", cname: "ghost.example.net"},
		{rel: "corp"}, // NODATA: vpn.corp exists below it
		{rel: "x.dev", a: []string{"192.0.2.99"}}, // wildcard
		{rel: "a.b.dev", a: []string{"192.0.2.99"}},
		{rel: "api.dev", a: []string{"192.0.2.40"}}, // defined names beat the wildcard
		{rel: "dev"}, // the wildcard's parent exists, with no records
		{rel: "x.corp", rcode: dnsmessage.RCodeNameError},
		{rel: "missing", rcode: dnsmessage.RCodeNameError},
		{rel: "slow", drop: true},
		{rel: "broken", rcode: dnsmessage.RCodeServerFailure},
	}
	for _, c := range cases {
		r := z.Answer(c.rel, origin)
		if r.RCode != c.rcode || r.Drop != c.drop || r.CNAME != c.cname || !slices.Equal(r.A, c.a) {
			t.Errorf("Answer(%q) = %+v, want rcode %v drop %v cname %q a %v", c.rel, r, c.rcode, c.drop, c.cname, c.a)
		}
	}
}

func TestHandler(t *testing.T) {
	z := mustParse(t, scenario)
	h := z.Handler([]string{"lab.example", "other.test"})
	r := h(dnsserver.Query{Name: "www.lab.example", Type: dnsmessage.TypeA})
	if !slices.Equal(r.A, []string{"192.0.2.10"}) || r.Delay != 5*time.Millisecond {
		t.Errorf("www.lab.example = %+v", r)
	}
	if r := h(dnsserver.Query{Name: "www.other.test", Type: dnsmessage.TypeA}); !slices.Equal(r.A, []string{"192.0.2.10"}) {
		t.Errorf("second origin: %+v", r)
	}
	if r := h(dnsserver.Query{Name: "www.elsewhere.test", Type: dnsmessage.TypeA}); r.RCode != dnsmessage.RCodeNameError {
		t.Errorf("out-of-zone name should be NXDOMAIN, got %+v", r)
	}
	if r := h(dnsserver.Query{Name: "slow.lab.example", Type: dnsmessage.TypeA}); !r.Drop || r.Delay != 0 {
		t.Errorf("TIMEOUT name: %+v", r)
	}
}

func TestRefuseAbove(t *testing.T) {
	z := mustParse(t, "$REFUSE-ABOVE 3\nwww A 192.0.2.10\n")
	h := z.Handler([]string{"lab.example"})
	refused := 0
	for range 10 {
		if h(dnsserver.Query{Name: "www.lab.example", Type: dnsmessage.TypeA}).RCode == dnsmessage.RCodeRefused {
			refused++
		}
	}
	if refused != 7 {
		t.Errorf("refused %d of 10 queries in one second, want 7", refused)
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{
		"",
		"# only comments\n",
		"www A 2001:db8::1",
		"www AAAA 192.0.2.1",
		"www A",
		"www MX mail",
		"www.lab.example. A 192.0.2.1",
		"www CNAME a\nwww A 192.0.2.1",
		"www A 192.0.2.1\nwww CNAME a",
		"www TIMEOUT\nwww A 192.0.2.1",
		"www A 192.0.2.1\nwww SERVFAIL",
		"www TIMEOUT now",
		"$DELAY soon\nwww A 192.0.2.1",
		"$REFUSE-ABOVE 0\nwww A 192.0.2.1",
		"$TTL 60\nwww A 192.0.2.1",
		"a..b A 192.0.2.1",
		"a.*.b A 192.0.2.1",
	} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("Parse(%q) succeeded, want an error", bad)
		}
	}
}

func TestParseErrorHasLineNumber(t *testing.T) {
	_, err := Parse(strings.NewReader("www A 192.0.2.1\n\nmail A nope\n"))
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("err = %v, want it to name line 3", err)
	}
}
