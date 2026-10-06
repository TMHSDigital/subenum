package subenum_test

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/pkg/subenum"
)

// zone answers from a small fixed table, so these tests reach the real
// resolver without leaving the machine.
func zone(t *testing.T) string {
	t.Helper()
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		switch strings.TrimSuffix(q.Name, ".lab.example") {
		case "www":
			return dnstest.Reply{A: []string{"192.0.2.10"}, AAAA: []string{"2001:db8::10"}}
		case "mail":
			return dnstest.Reply{A: []string{"192.0.2.20"}}
		case "blog":
			return dnstest.Reply{CNAME: "gone.example.net"}
		case "lab.example":
			return dnstest.Reply{A: []string{"192.0.2.1"}}
		}
		return dnstest.NXDomain
	})
	return srv.Addr
}

func names(results []subenum.Result) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		out = append(out, r.Name)
	}
	slices.Sort(out)
	return out
}

func TestScanAgainstLocalResolver(t *testing.T) {
	results, stats, err := subenum.Scan(context.Background(), subenum.Config{
		Domain:   "lab.example",
		Words:    []string{"www", "mail", "nope"},
		Resolver: zone(t),
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"mail.lab.example", "www.lab.example"}
	if got := names(results); !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
	if stats.Found != 2 || stats.NXDomain != 1 || stats.Total() != 3 {
		t.Errorf("stats = %+v, want 2 found and 1 nxdomain of 3", stats)
	}
	if stats.QueriesSent == 0 {
		t.Error("QueriesSent is 0, want the real lookups to be counted")
	}
	if stats.Aborted || stats.Wildcard {
		t.Errorf("Aborted = %v, Wildcard = %v, want both false", stats.Aborted, stats.Wildcard)
	}

	// www has both an A and an AAAA record, carried through to the caller.
	for _, r := range results {
		if r.Name != "www.lab.example" {
			continue
		}
		var got []string
		for _, rec := range r.Records {
			got = append(got, rec.Type+"="+rec.Value)
		}
		slices.Sort(got)
		if want := []string{"A=192.0.2.10", "AAAA=2001:db8::10"}; !slices.Equal(got, want) {
			t.Errorf("www records = %v, want %v", got, want)
		}
	}
}

func TestScanReportsTakeoverHint(t *testing.T) {
	results, stats, err := subenum.Scan(context.Background(), subenum.Config{
		Domain:   "lab.example",
		Words:    []string{"www", "blog"},
		Types:    []string{"A", "AAAA", "CNAME"},
		Resolver: zone(t),
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	hints := map[string]string{}
	for _, r := range results {
		hints[r.Name] = r.Takeover
	}
	// blog is a CNAME to a name that does not resolve.
	if hints["blog.lab.example"] != "dangling" {
		t.Errorf("blog takeover = %q, want %q", hints["blog.lab.example"], "dangling")
	}
	if hints["www.lab.example"] != "" {
		t.Errorf("www takeover = %q, want empty", hints["www.lab.example"])
	}
	if stats.Takeover != 1 {
		t.Errorf("Stats.Takeover = %d, want 1", stats.Takeover)
	}
}

func TestRunEndsWithExactlyOneDone(t *testing.T) {
	events, err := subenum.Run(context.Background(), subenum.Config{
		Domain:   "lab.example",
		Words:    []string{"www", "mail", "nope"},
		Resolver: zone(t),
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	var done, results int
	var last subenum.Kind
	for ev := range events {
		last = ev.Kind
		switch ev.Kind {
		case subenum.KindDone:
			done++
		case subenum.KindResult:
			results++
		}
	}
	if done != 1 {
		t.Errorf("got %d done events, want exactly 1", done)
	}
	if last != subenum.KindDone {
		t.Errorf("last event was %s, want done", last)
	}
	if results != 2 {
		t.Errorf("got %d results, want 2", results)
	}
}

func TestExcludeIsNeverQueried(t *testing.T) {
	results, stats, err := subenum.Scan(context.Background(), subenum.Config{
		Domain:   "lab.example",
		Words:    []string{"www", "mail"},
		Exclude:  []string{"mail.lab.example"},
		Resolver: zone(t),
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(results); !slices.Equal(got, []string{"www.lab.example"}) {
		t.Errorf("found %v, want only www", got)
	}
	if stats.Excluded != 1 {
		t.Errorf("Stats.Excluded = %d, want 1", stats.Excluded)
	}
}

func TestSimulateIsReproducibleAndSendsNothing(t *testing.T) {
	cfg := subenum.Config{
		Domain:   "example.com",
		Words:    []string{"www", "mail", "api", "dev", "stage", "vpn"},
		Simulate: true,
		Seed:     42,
	}
	first, stats, err := subenum.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := subenum.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names(first), names(second)) {
		t.Errorf("the same seed gave %v then %v", names(first), names(second))
	}
	if stats.QueriesSent != 0 {
		t.Errorf("QueriesSent = %d, want 0 for a simulated scan", stats.QueriesSent)
	}
}

func TestCancellationStopsTheScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, _, err := subenum.Scan(ctx, subenum.Config{
		Domain:   "example.com",
		Simulate: true, // the bundled wordlist; cancelled before it gets far
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if len(results) > 100 {
		t.Errorf("got %d results from a cancelled scan, want the scan to stop early", len(results))
	}
}

func TestZeroConfigUsesDefaults(t *testing.T) {
	// A simulated scan of a zero Config still enumerates the bundled list.
	_, stats, err := subenum.Scan(context.Background(), subenum.Config{
		Domain:   "example.com",
		Simulate: true,
		Seed:     7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(len(subenum.DefaultWords())); stats.Total() != want {
		t.Errorf("looked up %d names, want %d (the bundled wordlist)", stats.Total(), want)
	}
	// HitRate defaults to 15%, so a tenth to a fifth should resolve.
	if share := float64(stats.Found) / float64(stats.Total()); share < 0.10 || share > 0.20 {
		t.Errorf("resolved %.0f%% of names, want roughly the default 15%%", share*100)
	}
}

func TestDefaultWordsAreUsable(t *testing.T) {
	words := subenum.DefaultWords()
	if len(words) < 1000 {
		t.Fatalf("got %d words, want thousands", len(words))
	}
	for _, w := range words {
		if w == "" || strings.HasPrefix(w, "#") || strings.ContainsAny(w, " \t") {
			t.Fatalf("unusable entry %q: the list should be normalized", w)
		}
	}
	if !slices.Contains(words, "www") {
		t.Error("the bundled list does not contain www")
	}
	// The caller gets a copy it may modify.
	words[0] = "mutated"
	if subenum.DefaultWords()[0] == "mutated" {
		t.Error("DefaultWords shares its backing array between calls")
	}
}

func TestConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  subenum.Config
		want string
	}{
		{"no domain", subenum.Config{}, "Domain"},
		{"bad domain", subenum.Config{Domain: "not a domain"}, "Domain"},
		{"negative concurrency", subenum.Config{Domain: "example.com", Concurrency: -1}, "Concurrency"},
		{"negative timeout", subenum.Config{Domain: "example.com", Timeout: -time.Second}, "Timeout"},
		{"negative attempts", subenum.Config{Domain: "example.com", Attempts: -2}, "Attempts"},
		{"negative rate", subenum.Config{Domain: "example.com", Rate: -5}, "Rate"},
		{"negative max queries", subenum.Config{Domain: "example.com", MaxQueries: -5}, "MaxQueries"},
		{"negative depth", subenum.Config{Domain: "example.com", Depth: -1}, "Depth"},
		{"hit rate too high", subenum.Config{Domain: "example.com", Simulate: true, HitRate: 101}, "HitRate"},
		{"unknown record type", subenum.Config{Domain: "example.com", Types: []string{"MX"}}, "Types"},
		{"bad resolver", subenum.Config{Domain: "example.com", Resolver: "not-an-address"}, "Resolver"},
		{"bad exclude", subenum.Config{Domain: "example.com", Exclude: []string{"*"}}, "Exclude"},
		{"pool with simulate", subenum.Config{Domain: "example.com", Simulate: true, ResolverPool: []string{"192.0.2.1"}}, "ResolverPool"},
		{"empty pool", subenum.Config{Domain: "example.com", ResolverPool: []string{"   "}}, "ResolverPool"},
		{"no usable words", subenum.Config{Domain: "example.com", Words: []string{"", "# only a comment"}}, "wordlist"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			events, err := subenum.Run(context.Background(), c.cfg)
			if err == nil {
				t.Fatal("want an error")
			}
			if events != nil {
				t.Error("want no channel alongside the error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %q, want it to mention %q", err, c.want)
			}
			if !strings.HasPrefix(err.Error(), "subenum: ") {
				t.Errorf("err = %q, want it to name the package", err)
			}
		})
	}
}

func TestDomainIsNormalized(t *testing.T) {
	// A URL with a port and a trailing dot names the same domain.
	results, _, err := subenum.Scan(context.Background(), subenum.Config{
		Domain:   "https://LAB.example.:443/path",
		Words:    []string{"www"},
		Resolver: zone(t),
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(results); !slices.Equal(got, []string{"www.lab.example"}) {
		t.Errorf("found %v, want www.lab.example", got)
	}
}

func TestWildcardZoneIsRefusedUnlessForced(t *testing.T) {
	srv := dnstest.Start(t, func(dnstest.Query) dnstest.Reply {
		return dnstest.Reply{A: []string{"192.0.2.250"}} // every name resolves
	})
	cfg := subenum.Config{
		Domain:   "lab.example",
		Words:    []string{"www", "mail"},
		Resolver: srv.Addr,
		Timeout:  2 * time.Second,
	}
	_, stats, err := subenum.Scan(context.Background(), cfg)
	if err == nil {
		t.Fatal("want a wildcard zone to be refused")
	}
	if !strings.Contains(err.Error(), "lab.example") || !strings.Contains(err.Error(), "Force") {
		t.Errorf("err = %q, want it to name the domain and how to override", err)
	}
	if stats.Total() != 0 {
		t.Errorf("stats = %+v, want nothing scanned", stats)
	}

	// A scan that never starts still ends with one terminal event, so a
	// range loop over Run always sees Stats.
	events, err := subenum.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var done int
	var last subenum.Kind
	for ev := range events {
		last = ev.Kind
		if ev.Kind == subenum.KindDone {
			done++
		}
	}
	if done != 1 || last != subenum.KindDone {
		t.Errorf("refused scan sent %d done events, last was %s; want exactly 1 and done", done, last)
	}

	cfg.Force = true
	events, err = subenum.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var notices []string
	stats = subenum.Stats{}
	for ev := range events {
		switch ev.Kind {
		case subenum.KindNotice:
			notices = append(notices, ev.Notice.String())
		case subenum.KindDone:
			stats = ev.Stats
		}
	}
	if !slices.Contains(notices, "wildcard") {
		t.Errorf("notices = %v, want a wildcard notice", notices)
	}
	if !stats.Wildcard {
		t.Error("Stats.Wildcard is false, want true")
	}
	if stats.WildcardFiltered == 0 {
		t.Error("Stats.WildcardFiltered is 0, want the wildcard answers dropped")
	}
	if len(stats.WildcardFingerprint) == 0 {
		t.Error("Stats.WildcardFingerprint is empty, want the learned answer")
	}
}

func TestRateLimitIsApplied(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.Type == dnsmessage.TypeA && strings.HasPrefix(q.Name, "w") {
			return dnstest.Reply{A: []string{"192.0.2.10"}}
		}
		return dnstest.NXDomain
	})
	// 20 names, two record types each: 40 queries at 20 per second needs
	// at least a second.
	words := make([]string, 0, 20)
	for i := range 20 {
		words = append(words, string(rune('a'+i))+"host")
	}
	start := time.Now()
	if _, _, err := subenum.Scan(context.Background(), subenum.Config{
		Domain:   "lab.example",
		Words:    words,
		Resolver: srv.Addr,
		Timeout:  2 * time.Second,
		Rate:     20,
	}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Errorf("40 queries at 20/s took %s, want at least a second", elapsed)
	}
}

// TestBreakAndCancelLeaksNothing covers #112: the idiomatic
// `for ev := range events { break }` with a deferred cancel leaves no
// goroutine of the scan behind, even though the channel is never drained.
func TestBreakAndCancelLeaksNothing(t *testing.T) {
	defer subenum.SetDoneGrace(10 * time.Millisecond)()
	base := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			events, err := subenum.Run(ctx, subenum.Config{Domain: "example.com", Simulate: true, HitRate: 100, Seed: 1})
			if err != nil {
				t.Fatal(err)
			}
			for range events {
				break
			}
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > base+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base+2 {
		t.Errorf("%d goroutines remain after 5 abandoned runs, started with %d", n, base)
	}
}

// TestCancelThenDrainStillEndsWithDone: a caller that cancels and keeps
// reading still gets the final event.
func TestCancelThenDrainStillEndsWithDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	events, err := subenum.Run(ctx, subenum.Config{Domain: "example.com", Simulate: true, HitRate: 100, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	<-events
	cancel()
	last := subenum.Event{Kind: subenum.KindResult}
	for ev := range events {
		last = ev
	}
	if last.Kind != subenum.KindDone {
		t.Errorf("last event %v, want KindDone", last.Kind)
	}
}

// TestSubMillisecondTimeoutRoundsUp: a positive Timeout below the engine's
// 1ms resolution is rounded up, not rejected as zero.
func TestSubMillisecondTimeoutRoundsUp(t *testing.T) {
	if _, _, err := subenum.Scan(context.Background(), subenum.Config{Domain: "example.com", Words: []string{"www"}, Simulate: true, Timeout: 500 * time.Microsecond}); err != nil {
		t.Errorf("Timeout 500µs: %v", err)
	}
}

// TestStoppedScanEndsWithOneDone covers #99: a scan refused before it starts
// (here, an out-of-scope domain) still ends with exactly one KindDone, marked
// Stopped, after the KindError.
func TestStoppedScanEndsWithOneDone(t *testing.T) {
	events, err := subenum.Run(context.Background(), subenum.Config{
		Domain: "example.com", Words: []string{"www"}, Simulate: true, Exclude: []string{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []subenum.Kind
	var last subenum.Event
	for ev := range events {
		kinds = append(kinds, ev.Kind)
		last = ev
	}
	if len(kinds) != 2 || kinds[0] != subenum.KindError || last.Kind != subenum.KindDone || !last.Stopped {
		t.Errorf("events %v, last %+v; want an error, then one done with Stopped", kinds, last)
	}
}
