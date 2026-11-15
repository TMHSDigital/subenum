package subenum_test

import (
	"context"
	"net"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/pkg/subenum"
)

// zoneServer serves example.test from one local server that is also its
// only name server, allows AXFR when allow is set, and signs negative
// answers with denial. It points the package's transfers at its port.
func zoneServer(t *testing.T, allow bool, denial string) *dnstest.Server {
	t.Helper()
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch {
		case q.Type == dnsmessage.TypeAXFR && q.Name == "example.test":
			if !allow {
				return dnstest.Refused
			}
			return dnstest.Reply{Transfer: []string{"www.example.test", "admin-legacy.example.test"}}
		case q.Type == dnsmessage.TypeNS && q.Name == "example.test":
			return dnstest.Reply{NS: []string{"ns1.example.test"}}
		case q.Name == "ns1.example.test" && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"127.0.0.1"}}
		case q.Name == "ns1.example.test":
			return dnstest.Reply{}
		case q.Name == "admin-legacy.example.test" && q.Type == dnsmessage.TypeA:
			return dnstest.Reply{A: []string{"192.0.2.10"}}
		case q.Name == "admin-legacy.example.test":
			return dnstest.Reply{}
		}
		return dnstest.Reply{RCode: dnsmessage.RCodeNameError, Denial: denial}
	})
	_, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(subenum.SetZonePort(port))
	return srv
}

// TestProbeZone covers #314: the library reports an allowed transfer, its
// names and a walkable zone, as the CLI's -axfr does.
func TestProbeZone(t *testing.T) {
	srv := zoneServer(t, true, "nsec")
	info, err := subenum.ProbeZone(context.Background(), "Example.test.", subenum.ZoneOptions{Resolver: srv.Addr})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"admin-legacy", "www"}; !slices.Equal(info.Names, want) {
		t.Errorf("Names = %q, want %q", info.Names, want)
	}
	if want := []string{"ns1.example.test"}; !slices.Equal(info.TransferAllowed, want) {
		t.Errorf("TransferAllowed = %q, want %q", info.TransferAllowed, want)
	}
	if info.Denial != "nsec" {
		t.Errorf("Denial = %q, want nsec", info.Denial)
	}
}

// TestProbeZoneRefused: a refused transfer, the usual configuration, is
// not an error.
func TestProbeZoneRefused(t *testing.T) {
	srv := zoneServer(t, false, "nsec3")
	info, err := subenum.ProbeZone(context.Background(), "example.test", subenum.ZoneOptions{Resolver: srv.Addr})
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Names) != 0 || len(info.TransferAllowed) != 0 || info.Denial != "nsec3" {
		t.Errorf("info = %+v, want no names, no allowed servers and nsec3", info)
	}
	if n := srv.QueriesFor("example.test", dnsmessage.TypeAXFR); n != 1 {
		t.Errorf("AXFR queries = %d, want 1", n)
	}
}

// TestZoneTransferSource: the transfer's names are scanned like any other
// source's, and only those that resolve are reported.
func TestZoneTransferSource(t *testing.T) {
	srv := zoneServer(t, true, "")
	results, _, err := subenum.Scan(context.Background(), subenum.Config{
		Domain:   "example.test",
		Words:    []string{"mail"},
		Resolver: srv.Addr,
		Types:    []string{"A"},
		Sources:  []subenum.Source{subenum.ZoneTransfer(subenum.ZoneOptions{Resolver: srv.Addr})},
	})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range results {
		names = append(names, r.Name)
	}
	if want := []string{"admin-legacy.example.test"}; !slices.Equal(names, want) {
		t.Errorf("results = %q, want %q", names, want)
	}
	if len(results) == 1 && !slices.Equal(results[0].Sources, []string{"axfr"}) {
		t.Errorf("sources = %q, want [axfr], as the CLI labels a zone transfer (#273)", results[0].Sources)
	}
}

// TestProbeZoneErrors: bad options and a domain without name servers are
// errors.
func TestProbeZoneErrors(t *testing.T) {
	srv := zoneServer(t, true, "")
	for name, tc := range map[string]struct {
		domain string
		opts   subenum.ZoneOptions
	}{
		"bad domain":     {"not a domain", subenum.ZoneOptions{Resolver: srv.Addr}},
		"bad resolver":   {"example.test", subenum.ZoneOptions{Resolver: "nonsense:"}},
		"negative":       {"example.test", subenum.ZoneOptions{Resolver: srv.Addr, Timeout: -1}},
		"no nameservers": {"other.test", subenum.ZoneOptions{Resolver: srv.Addr}},
	} {
		if _, err := subenum.ProbeZone(context.Background(), tc.domain, tc.opts); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
