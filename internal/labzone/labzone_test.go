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
home     CNAME  @
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
		{rel: "home", cname: "lab.example", a: []string{"192.0.2.1"}}, // @ is the scanned domain (#115)
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

// TestAnswerNSMXTXT covers #194: NS and MX hosts resolve against the scanned
// domain like CNAME targets, and a TXT value is the rest of the line.
func TestAnswerNSMXTXT(t *testing.T) {
	z := mustParse(t, strings.Join([]string{
		"@     TXT \"v=spf1 include:_spf.example.net -all\"",
		"@     MX  10 mx1",
		"@     MX  20 mx.example.net.",
		"sub   NS  ns1.sub",
		"sub   NS  ns1.gone.example.net.",
	}, "\n"))
	apex := z.Answer("", "lab.example")
	if want := []string{"v=spf1 include:_spf.example.net -all"}; !slices.Equal(apex.TXT, want) {
		t.Errorf("TXT = %q, want %q", apex.TXT, want)
	}
	if want := []string{"10 mx1.lab.example", "20 mx.example.net"}; !slices.Equal(apex.MX, want) {
		t.Errorf("MX = %q, want %q", apex.MX, want)
	}
	if want := []string{"ns1.sub.lab.example", "ns1.gone.example.net"}; !slices.Equal(z.Answer("sub", "lab.example").NS, want) {
		t.Errorf("NS = %q, want %q", z.Answer("sub", "lab.example").NS, want)
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

// TestParseErrors pins the exact message for every directive and record
// type error, so a refactor of parseLine keeps what lab authors see.
func TestParseErrors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "no records defined"},
		{"# only comments\n", "no records defined"},
		{"www", "line 1: want <name> <type> [value]"},
		{"www A 2001:db8::1", `line 1: bad A address "2001:db8::1"`},
		{"www AAAA 192.0.2.1", `line 1: bad AAAA address "192.0.2.1"`},
		{"www A nope", `line 1: bad A address "nope"`},
		{"www A", "line 1: want <name> A <value>"},
		{"www a 192.0.2.1 extra", "line 1: want <name> A <value>"},
		{"www MX", "line 1: want <name> MX <value>"},
		{"www SRV x", "line 1: unknown type SRV (known: A, AAAA, CNAME, NS, MX, TXT, TIMEOUT, SERVFAIL, REFUSED, NXDOMAIN)"},
		{"www srv x", "line 1: unknown type srv (known: A, AAAA, CNAME, NS, MX, TXT, TIMEOUT, SERVFAIL, REFUSED, NXDOMAIN)"},
		{"www MX mail", "line 1: want <name> MX <preference> <host>"},
		{"www MX x mail", "line 1: bad MX preference \"x\""},
		{"www NS @", "line 1: bad NS host \"@\""},
		{"www CNAME a\nwww TXT hello", "line 2: www: a CNAME cannot be combined with other records"},
		{"www NS ns1\nwww CNAME a", "line 2: www: a CNAME cannot be combined with other records"},
		{"www.lab.example. A 192.0.2.1", "line 1: www.lab.example.: names are relative to the scanned domain; drop the trailing dot"},
		{"www CNAME a\nwww A 192.0.2.1", "line 2: www: a CNAME cannot be combined with other records"},
		{"www CNAME a\nwww AAAA 2001:db8::1", "line 2: www: a CNAME cannot be combined with other records"},
		{"www A 192.0.2.1\nwww CNAME a", "line 2: www: a CNAME cannot be combined with other records"},
		{"www CNAME a\nwww CNAME b", "line 2: www: a CNAME cannot be combined with other records"},
		{"www TIMEOUT\nwww A 192.0.2.1", "line 2: www: already defined as a failure"},
		{"www TIMEOUT\nwww CNAME a", "line 2: www: already defined as a failure"},
		{"www TIMEOUT\nwww NXDOMAIN", "line 2: www: a failure cannot be combined with other records for the same name"},
		{"www A 192.0.2.1\nwww SERVFAIL", "line 2: www: a failure cannot be combined with other records for the same name"},
		{"www CNAME a\nwww refused", "line 2: www: a failure cannot be combined with other records for the same name"},
		{"www TIMEOUT now", "line 1: TIMEOUT takes no value"},
		{"$DELAY", "line 1: want $DELAY <duration>, e.g. $DELAY 20ms"},
		{"$DELAY 1s 2s", "line 1: want $DELAY <duration>, e.g. $DELAY 20ms"},
		{"$DELAY soon\nwww A 192.0.2.1", `line 1: bad $DELAY "soon": want a duration up to 10s, e.g. 20ms`},
		{"$DELAY -1ms", `line 1: bad $DELAY "-1ms": want a duration up to 10s, e.g. 20ms`},
		{"$DELAY 11s", `line 1: bad $DELAY "11s": want a duration up to 10s, e.g. 20ms`},
		{"$REFUSE-ABOVE", "line 1: want $REFUSE-ABOVE <queries per second>"},
		{"$REFUSE-ABOVE 0\nwww A 192.0.2.1", `line 1: bad $REFUSE-ABOVE "0": want a positive number of queries per second`},
		{"$REFUSE-ABOVE many", `line 1: bad $REFUSE-ABOVE "many": want a positive number of queries per second`},
		{"$TTL 60\nwww A 192.0.2.1", "line 1: unknown directive $TTL (known: $DELAY, $REFUSE-ABOVE)"},
		{"$ttl", "line 1: unknown directive $ttl (known: $DELAY, $REFUSE-ABOVE)"},
		{"a..b A 192.0.2.1", `line 1: bad name "a..b"`},
		{"a.*.b A 192.0.2.1", `line 1: bad name "a.*.b"`},
		{"shop CNAME *.www", `line 1: bad CNAME target "*.www"`},
		{"shop CNAME a..b", `line 1: bad CNAME target "a..b"`},
		{"shop CNAME @.www", `line 1: bad CNAME target "@.www"`},
	} {
		_, err := Parse(strings.NewReader(tc.in))
		if err == nil || err.Error() != tc.want {
			t.Errorf("Parse(%q) error = %v, want %q", tc.in, err, tc.want)
		}
	}
}

// TestParseRecords covers every directive and record type that parses,
// including case folding and how values are normalised.
func TestParseRecords(t *testing.T) {
	z := mustParse(t, `
$delay 20ms
$refuse-above 7
WWW  a     192.0.2.10
www  A     192.0.2.11
www  aaaa  2001:DB8:0::10
v4m  AAAA  ::ffff:192.0.2.1
shop cname WWW.Example.NET.
home CNAME @
*.dev A 192.0.2.99
*    AAAA 2001:db8::99
t    timeout
s    servfail
r    REFUSED
n    nxdomain
`)
	if z.Delay != 20*time.Millisecond || z.RefuseAbove != 7 {
		t.Errorf("directives: Delay %v RefuseAbove %d, want 20ms and 7", z.Delay, z.RefuseAbove)
	}
	for _, tc := range []struct {
		name string
		wild bool
		want entry
	}{
		{name: "www", want: entry{a: []string{"192.0.2.10", "192.0.2.11"}, aaaa: []string{"2001:db8::10"}}},
		{name: "v4m", want: entry{aaaa: []string{"::ffff:192.0.2.1"}}},
		{name: "shop", want: entry{cname: "www.example.net."}},
		{name: "home", want: entry{cname: "@"}},
		{name: "dev", wild: true, want: entry{a: []string{"192.0.2.99"}}},
		{name: "", wild: true, want: entry{aaaa: []string{"2001:db8::99"}}},
	} {
		table := z.entries
		if tc.wild {
			table = z.wildcards
		}
		e := table[tc.name]
		if e == nil || !slices.Equal(e.a, tc.want.a) || !slices.Equal(e.aaaa, tc.want.aaaa) || e.cname != tc.want.cname || e.fail != nil {
			t.Errorf("entry %q (wild %v) = %+v, want %+v", tc.name, tc.wild, e, tc.want)
		}
	}
	for name, want := range map[string]dnsserver.Reply{
		"t": dnsserver.Dropped, "s": dnsserver.ServFail, "r": dnsserver.Refused, "n": dnsserver.NXDomain,
	} {
		if e := z.entries[name]; e == nil || e.fail == nil || e.fail.RCode != want.RCode || e.fail.Drop != want.Drop {
			t.Errorf("failure %q = %+v, want %+v", name, e, want)
		}
	}
	for _, name := range []string{"", "www", "dev", "t"} {
		if !z.exists[name] {
			t.Errorf("exists[%q] = false, want true", name)
		}
	}
}

func TestParseErrorHasLineNumber(t *testing.T) {
	_, err := Parse(strings.NewReader("www A 192.0.2.1\n\nmail A nope\n"))
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("err = %v, want it to name line 3", err)
	}
}
