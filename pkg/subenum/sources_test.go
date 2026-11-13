package subenum_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/pkg/subenum"
)

type staticSource []string

func (s staticSource) Names(context.Context, string) ([]string, error) { return s, nil }

type failingSource struct{}

func (failingSource) Names(context.Context, string) ([]string, error) {
	return nil, errors.New("index unavailable")
}

// TestSources covers #193: a source's names are scanned after Words, and a
// failing source is a notice, not a failed scan.
func TestSources(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "example.test", "www.example.test", "legacy.example.test":
			if q.Type == dnsmessage.TypeA {
				return dnstest.Reply{A: []string{"192.0.2.10"}}
			}
			return dnstest.Reply{}
		}
		return dnstest.NXDomain
	})
	events, err := subenum.Run(context.Background(), subenum.Config{
		Domain:   "example.test",
		Words:    []string{"www"},
		Resolver: srv.Addr,
		Types:    []string{"A"},
		Sources:  []subenum.Source{staticSource{"legacy", "www", "bad name!"}, failingSource{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	var notice *subenum.Event
	for ev := range events {
		switch {
		case ev.Kind == subenum.KindResult:
			names = append(names, ev.Result.Name)
		case ev.Kind == subenum.KindNotice && ev.Notice == subenum.NoticeSource:
			notice = &ev
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"legacy.example.test", "www.example.test"}) {
		t.Errorf("results = %q, want www from Words and legacy from the source", names)
	}
	if notice == nil {
		t.Error("the failing source sent no NoticeSource event")
	}
	if n := srv.QueriesFor("www.example.test", dnsmessage.TypeA); n != 1 {
		t.Errorf("www was looked up %d times; a source repeating a word must not add it twice", n)
	}
}

// TestSourcesIgnoredWhenSimulated: a simulation sends nothing off the
// machine, sources included.
func TestSourcesIgnoredWhenSimulated(t *testing.T) {
	asked := false
	src := sourceFunc(func() { asked = true })
	_, _, err := subenum.Scan(context.Background(), subenum.Config{Domain: "example.com", Words: []string{"www"}, Simulate: true, Seed: 1, Sources: []subenum.Source{src}})
	if err != nil {
		t.Fatal(err)
	}
	if asked {
		t.Error("a simulated scan asked its sources")
	}
}

type sourceFunc func()

func (f sourceFunc) Names(context.Context, string) ([]string, error) { f(); return nil, nil }

func TestBuiltinSources(t *testing.T) {
	if subenum.CertificateTransparency() == nil || subenum.WaybackMachine() == nil {
		t.Fatal("a built-in source is nil")
	}
}
