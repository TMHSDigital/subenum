package dns

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// TestTransfer covers #85: a server that allows AXFR gives every name in the
// zone, over TCP, in one query.
func TestTransfer(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.Type == dnsmessage.TypeAXFR && q.Name == "example.test" {
			return dnstest.Reply{Transfer: []string{"www.example.test", "Mail.Example.Test.", "dev.api.example.test", "www.example.test", "other.invalid"}}
		}
		return dnstest.Refused
	})
	names, err := Transfer(context.Background(), srv.Addr, "Example.Test.", 5*time.Second)
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if want := []string{"dev.api.example.test", "mail.example.test", "www.example.test"}; !slices.Equal(names, want) {
		t.Errorf("Transfer = %q, want %q (sorted, deduplicated, in the zone)", names, want)
	}
	if n := srv.QueriesFor("example.test", dnsmessage.TypeAXFR); n != 1 {
		t.Errorf("AXFR queries = %d, want 1", n)
	}
}

// TestTransferRefused: the usual configuration is a refusal, reported as
// ErrTransferRefused, whether the server answers REFUSED or answers the
// question without a transfer.
func TestTransferRefused(t *testing.T) {
	for _, c := range []struct {
		name  string
		reply dnstest.Reply
	}{
		{"REFUSED", dnstest.Refused},
		{"NOTAUTH", dnstest.Reply{RCode: rcodeNotAuth}},
		{"no transfer (NODATA)", dnstest.Reply{}},
	} {
		srv := dnstest.Start(t, func(dnstest.Query) dnstest.Reply { return c.reply })
		_, err := Transfer(context.Background(), srv.Addr, "example.test", 5*time.Second)
		if !errors.Is(err, ErrTransferRefused) {
			t.Errorf("%s: err = %v, want ErrTransferRefused", c.name, err)
		}
	}
}

// TestTransferTimeout: a server that never answers cannot hold the scan.
func TestTransferTimeout(t *testing.T) {
	srv := dnstest.Start(t, func(dnstest.Query) dnstest.Reply { return dnstest.Dropped })
	start := time.Now()
	_, err := Transfer(context.Background(), srv.Addr, "example.test", 300*time.Millisecond)
	if err == nil {
		t.Fatal("Transfer from a silent server succeeded")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Transfer took %v despite a 300ms timeout", elapsed)
	}
}
