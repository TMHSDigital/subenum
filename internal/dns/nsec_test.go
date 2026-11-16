package dns

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// TestProbeDenial covers #234: the denial-of-existence records an
// authoritative server returns for a missing name tell whether the zone can
// be walked.
func TestProbeDenial(t *testing.T) {
	for _, c := range []struct {
		denial string
		rcode  dnstest.Reply
		want   Denial
	}{
		{"nsec", dnstest.NXDomain, DenialNSEC},
		{"nsec3", dnstest.NXDomain, DenialNSEC3},
		{"", dnstest.NXDomain, DenialNone},
		{"nsec", dnstest.Reply{}, DenialNSEC}, // NODATA proves absence too
	} {
		var (
			mu    sync.Mutex
			asked string // written by the server's handler goroutine
		)
		srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
			mu.Lock()
			asked = q.Name
			mu.Unlock()
			r := c.rcode
			r.Denial = c.denial
			return r
		})
		got, err := ProbeDenial(context.Background(), srv.Addr, "Example.Test.", 5*time.Second)
		if err != nil {
			t.Fatalf("%q: %v", c.denial, err)
		}
		if got != c.want {
			t.Errorf("%q: denial = %q, want %q", c.denial, got, c.want)
		}
		mu.Lock()
		defer mu.Unlock()
		if !strings.HasSuffix(asked, ".example.test") || strings.Count(asked, ".") != 2 {
			t.Errorf("%q: probed %q, want a random label under example.test", c.denial, asked)
		}
	}
}

// TestProbeDenialRetriesOverTCP covers #305: a truncated UDP answer is asked
// again over TCP, and the denial records are read from the TCP answer.
func TestProbeDenialRetriesOverTCP(t *testing.T) {
	var udp, tcp atomic.Int64
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.TCP {
			tcp.Add(1)
		} else {
			udp.Add(1)
		}
		r := dnstest.NXDomain
		r.Denial = "nsec"
		r.Truncate = true
		return r
	})
	got, err := ProbeDenial(context.Background(), srv.Addr, "example.test", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != DenialNSEC {
		t.Errorf("denial = %q, want %q", got, DenialNSEC)
	}
	if u, c := udp.Load(), tcp.Load(); u != 1 || c != 1 {
		t.Errorf("%d UDP and %d TCP queries, want 1 and 1", u, c)
	}
}

func TestProbeDenialFailure(t *testing.T) {
	srv := dnstest.Start(t, func(dnstest.Query) dnstest.Reply { return dnstest.ServFail })
	if _, err := ProbeDenial(context.Background(), srv.Addr, "example.test", 5*time.Second); err == nil {
		t.Error("SERVFAIL was not an error")
	}
	silent := dnstest.Start(t, func(dnstest.Query) dnstest.Reply { return dnstest.Dropped })
	if _, err := ProbeDenial(context.Background(), silent.Addr, "example.test", 300*time.Millisecond); err == nil {
		t.Error("a silent server was not an error")
	}
}
