package subenum_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
	"github.com/TMHSDigital/subenum/internal/libhook"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/pkg/subenum"
)

// zone answers from a small fixed table, so these tests reach the real
// resolver without leaving the machine.
func zone(t *testing.T) string {
	t.Helper()
	return labServer(t).Addr
}

// labServer is zone's server, for tests that count the queries it gets.
func labServer(t *testing.T) *dnstest.Server {
	t.Helper()
	return dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
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

// TestScanTakeoverProviders covers #219: Config.TakeoverProviders makes a
// CNAME target the built-in list does not know a provider: hint, and
// TakeoverProvidersOnly with no entries matches nothing.
func TestScanTakeoverProviders(t *testing.T) {
	scan := func(c subenum.Config) (map[string]string, error) {
		c.Domain, c.Words, c.Types = "lab.example", []string{"www", "blog"}, []string{"A", "AAAA", "CNAME"}
		c.Resolver, c.Timeout = zone(t), 2*time.Second
		results, _, err := subenum.Scan(context.Background(), c)
		hints := map[string]string{}
		for _, r := range results {
			hints[r.Name] = r.Takeover
		}
		return hints, err
	}
	hints, err := scan(subenum.Config{TakeoverProviders: []subenum.TakeoverProvider{{Suffix: "example.net", Name: "example-host"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := hints["blog.lab.example"]; got != "dangling:example-host" {
		t.Errorf("blog takeover = %q, want dangling:example-host", got)
	}
	if _, err := scan(subenum.Config{TakeoverProviders: []subenum.TakeoverProvider{{Suffix: "example.net", Name: "Bad Name"}}}); err == nil {
		t.Error("an invalid provider name was accepted")
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

// TestSimulateSeedZeroIsRandom covers #154: Seed 0 picks a random seed, so
// two scans of the same words differ.
func TestSimulateSeedZeroIsRandom(t *testing.T) {
	words := make([]string, 0, 200)
	for i := range 200 {
		words = append(words, fmt.Sprintf("host%d", i))
	}
	cfg := subenum.Config{Domain: "example.com", Words: words, Simulate: true}
	first, _, err := subenum.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := subenum.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, b := names(first), names(second)
	slices.Sort(a)
	slices.Sort(b)
	if slices.Equal(a, b) {
		t.Errorf("Seed 0 gave the same results twice: %v", a)
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

// TestValidateMatchesRun covers #378: Validate reports what Run would refuse,
// without starting a scan.
func TestValidateMatchesRun(t *testing.T) {
	for name, cfg := range map[string]subenum.Config{
		"types":   {Domain: "example.com", Simulate: true, Types: []string{"CAA"}},
		"words":   {Domain: "example.com", Simulate: true, Words: []string{}},
		"exclude": {Domain: "example.com", Simulate: true, Exclude: []string{"*."}},
	} {
		err := cfg.Validate()
		if err == nil {
			t.Errorf("%s: Validate accepted an invalid config", name)
			continue
		}
		if _, runErr := subenum.Run(context.Background(), cfg); runErr == nil || runErr.Error() != err.Error() {
			t.Errorf("%s: Validate %v, Run %v", name, err, runErr)
		}
	}
	if err := (subenum.Config{Domain: "example.com", Simulate: true}).Validate(); err != nil {
		t.Errorf("valid config: %v", err)
	}
	if err := (subenum.Config{Domain: "example.com", Words: []string{}}).Validate(); !errors.Is(err, subenum.ErrNoWords) {
		t.Errorf("empty words: got %v, want ErrNoWords", err)
	}
	// #403: a RecursiveWords list with nothing usable is refused too.
	if err := (subenum.Config{Domain: "example.com", Simulate: true, Recursive: true, Depth: 2, RecursiveWords: []string{"bad_label!"}}).Validate(); !errors.Is(err, subenum.ErrNoWords) {
		t.Errorf("empty recursive words: got %v, want ErrNoWords", err)
	}
}

// TestValidateNamesConfigFields covers #414: the range checks Config shares
// with the CLI and TUI (scan.Options.Validate) report the Config field.
func TestValidateNamesConfigFields(t *testing.T) {
	for field, cfg := range map[string]subenum.Config{
		"Rate":            {Domain: "example.com", Simulate: true, Rate: -1},
		"MaxQueries":      {Domain: "example.com", Simulate: true, MaxQueries: -1},
		"HitRate":         {Domain: "example.com", Simulate: true, HitRate: 101},
		"MaxDuration":     {Domain: "example.com", Simulate: true, MaxDuration: -time.Second},
		"RatePerResolver": {Domain: "example.com", RatePerResolver: -1},
		"Resolver":        {Domain: "example.com", Resolver: "not a resolver"},
	} {
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), field) || !strings.HasPrefix(err.Error(), "subenum: ") {
			t.Errorf("%s: Validate = %v, want a subenum error naming %s", field, err, field)
		}
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
		{"negative rate per resolver", subenum.Config{Domain: "example.com", RatePerResolver: -5}, "RatePerResolver"},
		{"negative max queries", subenum.Config{Domain: "example.com", MaxQueries: -5}, "MaxQueries"},
		{"negative depth", subenum.Config{Domain: "example.com", Depth: -1}, "Depth"},
		{"hit rate too high", subenum.Config{Domain: "example.com", Simulate: true, HitRate: 101}, "HitRate"},
		{"unknown record type", subenum.Config{Domain: "example.com", Types: []string{"CAA"}}, "Types"},
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

// TestMaxDuration covers #190: a scan that outlasts its budget returns
// without an error, with the untested names counted and Expired set.
func TestMaxDuration(t *testing.T) {
	words := make([]string, 0, 40)
	for i := range 40 {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	// 40 names at 10/s need 4 s; the budget allows about a tenth of that.
	_, stats, err := subenum.Scan(context.Background(), subenum.Config{
		Domain: "example.com", Words: words, Simulate: true, Seed: 1,
		Concurrency: 1, Rate: 10, MaxDuration: 400 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !stats.Expired || stats.Skipped == 0 || stats.Skipped+stats.Found+stats.NXDomain != 40 {
		t.Errorf("stats %+v, want Expired with every name either tested or skipped", stats)
	}
	if _, _, err := subenum.Scan(context.Background(), subenum.Config{Domain: "example.com", Simulate: true, MaxDuration: -time.Second}); err == nil {
		t.Error("negative MaxDuration accepted")
	}
}

// TestInconclusiveListOff covers #349: Stats.Inconclusive lists the names
// without an answer, except in a scan subenum mcp starts through
// internal/libhook with the list turned off, which keeps none (#367).
func TestInconclusiveListOff(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		// "bad-", not "bad": the wildcard probe's random hex label can start
		// with "bad", and refusing it fails the scan.
		if strings.HasPrefix(q.Name, "bad-") {
			return dnstest.Refused
		}
		return dnstest.NXDomain
	})
	cfg := subenum.Config{Domain: "lab.example", Words: []string{"bad-1", "ok", "bad-2"}, Resolver: srv.Addr,
		Timeout: 10 * time.Second, Attempts: 1}
	_, stats, err := subenum.Scan(context.Background(), cfg)
	if err != nil || len(stats.Inconclusive) != 2 {
		t.Fatalf("Scan: err %v, inconclusive %q; want the two refused names", err, stats.Inconclusive)
	}
	events, err := libhook.Run[subenum.Config, subenum.Event](context.Background(), cfg, func(o *scan.Options) { o.ListInconclusive = false })
	if err != nil {
		t.Fatal(err)
	}
	stats = subenum.Stats{}
	for ev := range events {
		if ev.Kind == subenum.KindDone {
			stats = ev.Stats
		}
	}
	if stats.Inconclusive != nil || stats.Refused != 2 {
		t.Errorf("list off: inconclusive %q, refused %d; want no list and the two refusals counted", stats.Inconclusive, stats.Refused)
	}
}

// TestNoAbortScanSucceedsDespiteFailingLookups covers #149: under NoAbort
// the reliability guard only warns, so a completed Scan returns no error,
// while Run still reports the warning.
func TestNoAbortScanSucceedsDespiteFailingLookups(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if strings.HasPrefix(q.Name, "bad-") {
			return dnstest.Refused
		}
		return dnstest.NXDomain
	})
	words := make([]string, 0, 300)
	for i := range 300 {
		if i%2 == 0 {
			words = append(words, fmt.Sprintf("bad-%d", i))
		} else {
			words = append(words, fmt.Sprintf("ok%d", i))
		}
	}
	cfg := subenum.Config{
		Domain:   "lab.example",
		Words:    words,
		Resolver: srv.Addr,
		// The server answers every query at once, so a long timeout costs
		// nothing and keeps a loaded machine from failing the preflight (#289).
		Timeout:  10 * time.Second,
		Attempts: 1,
		NoAbort:  true,
	}
	results, stats, err := subenum.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Scan with NoAbort returned %v, want nil", err)
	}
	if stats.Aborted || stats.Total() != int64(len(words)) {
		t.Fatalf("stats = %+v, want a complete scan of %d names", stats, len(words))
	}
	if len(results) != 0 {
		t.Errorf("results = %v, want none", names(results))
	}

	events, err := subenum.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	warned := false
	for ev := range events {
		warned = warned || ev.Kind == subenum.KindError
		// The events say the warning was not fatal and the scan did not
		// fail, so a consumer needs no rule of its own (#308).
		if ev.Fatal || ev.Failed {
			t.Errorf("under NoAbort: %v event with Fatal %v, Failed %v; want neither", ev.Kind, ev.Fatal, ev.Failed)
		}
	}
	if !warned {
		t.Error("Run sent no KindError warning from the reliability guard")
	}

	cfg.NoAbort = false
	if _, stats, err := subenum.Scan(context.Background(), cfg); err == nil || !stats.Aborted {
		t.Errorf("without NoAbort: err = %v, Aborted = %v; want an error and an aborted scan", err, stats.Aborted)
	}
	events, err = subenum.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	fatal, failed := false, false
	for ev := range events {
		fatal = fatal || (ev.Kind == subenum.KindError && ev.Fatal)
		failed = failed || (ev.Kind == subenum.KindDone && ev.Failed)
	}
	if !fatal || !failed {
		t.Errorf("without NoAbort: fatal KindError %v, KindDone.Failed %v; want both", fatal, failed)
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

// TestScanThroughResolverPool covers #322: Config.ResolverPool reaches the
// engine. Every name is found, both members take lookups, and the names that
// do not exist are asked only of the pool; Config.Resolver, the trusted
// resolver, confirms the hits and is not asked about the misses.
func TestScanThroughResolverPool(t *testing.T) {
	trusted, a, b := labServer(t), labServer(t), labServer(t)
	results, stats, err := subenum.Scan(context.Background(), subenum.Config{
		Domain:       "lab.example",
		Words:        []string{"www", "mail", "nope", "gone"},
		Types:        []string{"A"},
		Resolver:     trusted.Addr,
		ResolverPool: []string{a.Addr, b.Addr},
		Timeout:      10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := names(results), []string{"mail.lab.example", "www.lab.example"}; !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
	if stats.PoolHits != 2 || stats.Confirmed != 2 {
		t.Errorf("PoolHits = %d, Confirmed = %d; want both 2", stats.PoolHits, stats.Confirmed)
	}
	if a.Queries() == 0 || b.Queries() == 0 {
		t.Errorf("pool members got %d and %d queries, want both to take part", a.Queries(), b.Queries())
	}
	for _, name := range []string{"nope.lab.example", "gone.lab.example"} {
		if n := trusted.QueriesFor(name, dnsmessage.TypeA); n != 0 {
			t.Errorf("Config.Resolver got %d queries for %s, want the pool to answer it", n, name)
		}
	}
}

// TestRatePerResolverIsApplied covers #322: RatePerResolver caps each pool
// member. Only the lower bound the cap implies is checked, as
// TestRateLimitIsApplied does.
func TestRatePerResolverIsApplied(t *testing.T) {
	trusted, a, b := labServer(t), labServer(t), labServer(t)
	words := make([]string, 0, 10)
	for i := range 10 {
		words = append(words, fmt.Sprintf("host%d", i))
	}
	const perSecond = 5
	start := time.Now()
	if _, _, err := subenum.Scan(context.Background(), subenum.Config{
		Domain:          "lab.example",
		Words:           words,
		Types:           []string{"A"},
		Resolver:        trusted.Addr,
		ResolverPool:    []string{a.Addr, b.Addr},
		RatePerResolver: perSecond,
		Timeout:         10 * time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	// 10 lookups over two members: the busier one takes at least 5, and the
	// cap spaces them a fifth of a second apart.
	busiest := max(a.Queries(), b.Queries())
	if busiest < 5 {
		t.Fatalf("pool members got %d and %d queries, want at least 10 between them", a.Queries(), b.Queries())
	}
	if floor := time.Duration(5-1) * time.Second / perSecond; elapsed < floor {
		t.Errorf("scan took %s, under the %s that 5 lookups on one member need at %d/s", elapsed, floor, perSecond)
	}
}

// TestConfigErrorsNameTheField covers #322's error returns that
// TestConfigErrors does not reach: a pool entry that is not an address, and
// a provider suffix the takeover list parser rejects.
func TestConfigErrorsNameTheField(t *testing.T) {
	cases := []struct {
		name   string
		cfg    subenum.Config
		prefix string
	}{
		{"bad pool entry", subenum.Config{Domain: "example.com", ResolverPool: []string{"not an address"}}, "subenum: ResolverPool: "},
		{"bad provider suffix", subenum.Config{Domain: "example.com", TakeoverProviders: []subenum.TakeoverProvider{{Suffix: "example.net/path", Name: "example-host"}}}, "subenum: TakeoverProviders: line 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			events, err := subenum.Run(context.Background(), c.cfg)
			if err == nil || events != nil {
				t.Fatalf("err = %v, events %v; want an error and no channel", err, events)
			}
			if !strings.HasPrefix(err.Error(), c.prefix) {
				t.Errorf("err = %q, want it to start with %q", err, c.prefix)
			}
		})
	}
}

// notices runs cfg and returns the Notice of each KindNotice event.
func notices(t *testing.T, cfg subenum.Config) []subenum.Notice {
	t.Helper()
	events, err := subenum.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out []subenum.Notice
	for ev := range events {
		if ev.Kind == subenum.KindNotice {
			out = append(out, ev.Notice)
		}
	}
	return out
}

// TestRecursiveWildcardBranchNotice covers #322: a recursive scan that finds
// a subdomain answering for every name below it skips that branch with a
// NoticeSkip.
func TestRecursiveWildcardBranchNotice(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if q.Type != dnsmessage.TypeA {
			return dnstest.NXDomain
		}
		switch name := strings.TrimSuffix(q.Name, "."); {
		case name == "dev.lab.example", strings.HasSuffix(name, ".dev.lab.example"):
			return dnstest.Reply{A: []string{"192.0.2.30"}}
		case name == "www.lab.example", name == "lab.example":
			return dnstest.Reply{A: []string{"192.0.2.10"}}
		}
		return dnstest.NXDomain
	})
	got := notices(t, subenum.Config{
		Domain: "lab.example", Words: []string{"dev", "www"}, Types: []string{"A"},
		Resolver: srv.Addr, Timeout: 10 * time.Second, Recursive: true, Depth: 2,
	})
	if !slices.Contains(got, subenum.NoticeSkip) {
		t.Errorf("notices = %v, want a %v", got, subenum.NoticeSkip)
	}
}

// TestAutoRateNotice covers #322: under AutoRate, a run of failing lookups
// slows the scan down with a NoticeRate instead of stopping it.
func TestAutoRateNotice(t *testing.T) {
	srv := dnstest.Start(t, func(q dnstest.Query) dnstest.Reply {
		if strings.HasPrefix(q.Name, "bad-") {
			return dnstest.Refused
		}
		return dnstest.NXDomain
	})
	// Failures first, so the first window AutoRate judges is a bad one.
	words := make([]string, 0, 400)
	for i := range 300 {
		words = append(words, fmt.Sprintf("bad-%d", i))
	}
	for i := range 100 {
		words = append(words, fmt.Sprintf("ok%d", i))
	}
	got := notices(t, subenum.Config{
		Domain: "lab.example", Words: words, Types: []string{"A"}, Resolver: srv.Addr,
		Timeout: 10 * time.Second, Attempts: 1, AutoRate: true,
	})
	if !slices.Contains(got, subenum.NoticeRate) {
		t.Errorf("notices = %v, want a %v", got, subenum.NoticeRate)
	}
}
