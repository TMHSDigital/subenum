package subenum_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/pkg/subenum"
)

type staticSource []string

func (s staticSource) Names(context.Context, string) ([]string, error) { return s, nil }

type failingSource struct{}

func (failingSource) Names(context.Context, string) ([]string, error) {
	return nil, errors.New("index unavailable")
}

// namedSource is a source with a Name method, which labels its results.
type namedSource struct {
	name  string
	names []string
}

func (s namedSource) Name() string                                    { return s.name }
func (s namedSource) Names(context.Context, string) ([]string, error) { return s.names, nil }

// TestSources covers #193: a source's names are scanned after Words, and a
// failing source is a notice, not a failed scan. Each result names what
// proposed it (#273).
func TestSources(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch q.Name {
		case "example.test", "www.example.test", "legacy.example.test", "cmdb.example.test":
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
		Sources: []subenum.Source{staticSource{"legacy", "www", "bad name!"}, failingSource{},
			namedSource{"inventory", []string{"cmdb", "legacy"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string][]string{}
	var notice *subenum.Event
	for ev := range events {
		switch {
		case ev.Kind == subenum.KindResult:
			sources[ev.Result.Name] = ev.Result.Sources
		case ev.Kind == subenum.KindNotice && ev.Notice == subenum.NoticeSource:
			notice = &ev
		}
	}
	want := map[string][]string{
		"www.example.test":    {"wordlist", "Sources[0]"},
		"legacy.example.test": {"Sources[0]", "inventory"},
		"cmdb.example.test":   {"inventory"},
	}
	if !reflect.DeepEqual(sources, want) {
		t.Errorf("results and their sources = %q, want %q", sources, want)
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

type truncatedSource []string

func (s truncatedSource) Names(context.Context, string) ([]string, error) {
	return s, &passive.Truncated{Source: "wayback", Why: "the index returned its limit"}
}

// TestTruncatedSourceIsScanned covers #272: a source that stopped at a
// limit still has its names scanned, with a notice that some may be missing.
func TestTruncatedSourceIsScanned(t *testing.T) {
	srv := dnstest.Start(t, func(dnstest.Query) dnstest.Reply { return dnstest.NXDomain })
	events, err := subenum.Run(context.Background(), subenum.Config{
		Domain: "example.test", Words: []string{"www"}, Resolver: srv.Addr, Types: []string{"A"},
		Sources: []subenum.Source{truncatedSource{"old"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var notice string
	var stats subenum.Stats
	for ev := range events {
		switch {
		case ev.Kind == subenum.KindNotice && ev.Notice == subenum.NoticeSource:
			notice = ev.Message
		case ev.Kind == subenum.KindDone:
			stats = ev.Stats
		}
	}
	if stats.NXDomain != 2 {
		t.Errorf("looked up %d names, want www and the truncated source's old", stats.NXDomain)
	}
	if !strings.Contains(notice, "truncated") || !strings.Contains(notice, "scanning its 1 names") {
		t.Errorf("notice = %q, want it to say the source was truncated and its names scanned", notice)
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
