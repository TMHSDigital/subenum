package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/dnstest"
	"golang.org/x/net/dns/dnsmessage"
)

// TestSRVNames covers #419: the built-in list holds _service._proto names
// that pass the wordlist's checks, without duplicates.
func TestSRVNames(t *testing.T) {
	names := srvNames()
	if len(names) < 30 || len(names) > 60 {
		t.Errorf("%d service names, want 30 to 60", len(names))
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] || !strings.HasPrefix(n, "_") || strings.Count(n, ".") != 1 {
			t.Errorf("bad or repeated service name %q", n)
		}
		seen[n] = true
	}
	if !seen["_sip._tcp"] || !seen["_autodiscover._tcp"] {
		t.Error("common service names are missing")
	}
}

// TestE2ESRV covers #419's -srv: the service names are looked up under the
// target and reported with source srv, a service whose target host does
// not exist is a dangling-srv takeover candidate, -srv without SRV in -type
// is refused, and -dry-run counts the names.
func TestE2ESRV(t *testing.T) {
	t.Parallel()
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Name == "example.com":
			return dnstest.Reply{}
		case q.Name == "www.example.com" && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"192.0.2.10"}}
		case q.Name == "www.example.com":
			return dnstest.Reply{}
		case q.Name == "_sip._tcp.example.com" && q.Type == dnsmessage.TypeSRV:
			return dnstest.Reply{SRV: []string{"10 5 5060 www.example.com"}}
		case q.Name == "_ldap._tcp.example.com" && q.Type == dnsmessage.TypeSRV:
			return dnstest.Reply{SRV: []string{"0 0 389 dc-gone.example.com"}}
		case q.Name == "_sip._tcp.example.com" || q.Name == "_ldap._tcp.example.com":
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	wl := writeFile(t, "wl.txt", "www\n")
	args := append(localArgs("-dns-server", srv.Addr, "-type", "A,SRV", "-progress=false", "-format", "jsonl", "-w", wl, "-srv"), "example.com")
	code, out := runCLIWith(t, runArgs{args: args})
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	got := seenResults(t, out)
	if r := got["_sip._tcp.example.com"]; !slices.Equal(r.Sources, []string{"srv"}) || len(r.Records) != 1 || r.Records[0] != (dns.Record{Type: "SRV", Value: "10 5 5060 www.example.com"}) {
		t.Errorf("_sip._tcp: %+v, want its SRV record with source srv", r)
	}
	if r := got["_ldap._tcp.example.com"]; r.Takeover != dns.DanglingSRV {
		t.Errorf("_ldap._tcp: takeover %q, want %s", r.Takeover, dns.DanglingSRV)
	}
	if r := got["www.example.com"]; !slices.Equal(r.Sources, []string{"wordlist"}) {
		t.Errorf("www: sources %v", r.Sources)
	}

	if code, out := runCLIMerged(t, "-simulate", "-srv", "-w", wl, "example.com"); code == exitOK || !strings.Contains(out, "add SRV to -type") {
		t.Errorf("-srv without SRV: exit %d\n%s", code, out)
	}

	_, plans := dryRunPlans(t, "-simulate", "-type", "A,SRV", "-w", wl, "-srv", "example.com")
	if len(plans) != 1 || plans[0].Candidates != 1+len(srvNames()) {
		t.Errorf("dry run: %+v, want %d candidates", plans, 1+len(srvNames()))
	}
}
