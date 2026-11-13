package main

import (
	"reflect"
	"slices"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// TestResultLogCompact covers #183: without full, records are dropped but
// everything else a resumed run re-emits survives, in order.
func TestResultLogCompact(t *testing.T) {
	a := []dns.Record{{Type: "A", Value: "192.0.2.1"}}
	in := []output.Result{
		{Result: scan.Result{Subdomain: "www.example.com", Records: a, Simulated: true}},
		{Result: scan.Result{Subdomain: "blog.example.com", Records: a, Simulated: true, Takeover: "dangling"}},
		{Result: scan.Result{Subdomain: "intra.example.com", Records: a, Simulated: true, Internal: "private"}},
		{Result: scan.Result{Subdomain: "api-dev.example.com", Records: a, Simulated: true}, Permutation: true},
		{Result: scan.Result{Subdomain: "mail.example.com", Records: a, Simulated: true}},
	}
	var l resultLog
	for _, r := range in {
		l.add(r)
	}
	got := l.results()
	if len(got) != len(in) {
		t.Fatalf("results() returned %d results, want %d", len(got), len(in))
	}
	for i, r := range got {
		want := in[i]
		if want.Takeover == "" && want.Internal == "" && !want.Permutation {
			want.Records = nil // plain results lose only their records
		}
		if !reflect.DeepEqual(r, want) {
			t.Errorf("result %d = %+v, want %+v", i, r, want)
		}
	}
	if names := l.mainPassNames(); !slices.Equal(names, []string{"www.example.com", "blog.example.com", "intra.example.com", "mail.example.com"}) {
		t.Errorf("mainPassNames() = %q, want every name but the permutation hit", names)
	}
	if len(l.extra) != 3 {
		t.Errorf("compact log kept %d whole results, want 3 (takeover, internal, permutation)", len(l.extra))
	}
}

// TestResultLogFull keeps every result whole, records included.
func TestResultLogFull(t *testing.T) {
	in := []output.Result{
		{Result: scan.Result{Subdomain: "www.example.com", Records: []dns.Record{{Type: "A", Value: "192.0.2.1"}}}},
		{Result: scan.Result{Subdomain: "x.example.com"}, Permutation: true},
	}
	l := resultLog{full: true}
	for _, r := range in {
		l.add(r)
	}
	if !reflect.DeepEqual(l.results(), in) {
		t.Errorf("results() = %+v, want %+v", l.results(), in)
	}
	if names := l.mainPassNames(); !slices.Equal(names, []string{"www.example.com"}) {
		t.Errorf("mainPassNames() = %q", names)
	}
	if l.names != nil {
		t.Error("a full log should not also keep names")
	}
}

func TestResultLogEmpty(t *testing.T) {
	var l resultLog
	if l.results() != nil || len(l.mainPassNames()) != 0 {
		t.Error("an empty log should have no results")
	}
}
