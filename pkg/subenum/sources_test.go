package subenum_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

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

// rendezvousSource answers only once every source sharing its WaitGroup has
// been asked, so sources asked one after another would wait forever.
type rendezvousSource struct {
	wg    *sync.WaitGroup
	names []string
}

func (s rendezvousSource) Names(ctx context.Context, _ string) ([]string, error) {
	s.wg.Done()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return s.names, nil
	case <-time.After(5 * time.Second):
		return nil, errors.New("the other source was never asked: sources ran one at a time")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestSourcesRunAtOnce covers #271: a target's sources are asked
// concurrently, so their latencies do not add up.
func TestSourcesRunAtOnce(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)
	srv := dnstest.Start(t, func(dnstest.Query) dnstest.Reply { return dnstest.NXDomain })
	start := time.Now()
	_, stats, err := subenum.Scan(context.Background(), subenum.Config{
		Domain: "example.test", Words: []string{"www"}, Resolver: srv.Addr, Types: []string{"A"},
		Sources: []subenum.Source{rendezvousSource{&wg, []string{"a"}}, rendezvousSource{&wg, []string{"b"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("sources took %v: they ran one at a time", time.Since(start))
	}
	if got := stats.NXDomain; got != 3 {
		t.Errorf("looked up %d names, want www plus both sources' names", got)
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
