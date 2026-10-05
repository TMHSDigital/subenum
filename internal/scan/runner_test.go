package scan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
)

// makeEntries builds a synthetic wordlist of n prefixes.
func makeEntries(n int) []string {
	entries := make([]string, n)
	for i := range entries {
		entries[i] = "p" + itoa(i)
	}
	return entries
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// TestRunSimulateConcurrent runs a simulate-mode scan with concurrency > 1 and
// asserts an EventDone arrives with Processed == Total. Under -race this also
// exercises the rand fix (simulate) and the ticker shutdown fix.
func TestRunSimulateConcurrent(t *testing.T) {
	total := int64(2000)
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(int(total)),
		Concurrency: 16,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     50,
		Attempts:    1,
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)

	var done *Event
	for ev := range events {
		if ev.Kind == EventDone {
			e := ev
			done = &e
		}
	}

	if done == nil {
		t.Fatal("no EventDone received")
	}
	if done.Total != total {
		t.Errorf("EventDone.Total = %d, want %d", done.Total, total)
	}
	if done.Processed != total {
		t.Errorf("EventDone.Processed = %d, want %d", done.Processed, total)
	}
}

// TestRunRecursiveEnqueuesChildren exercises the restructured queue lifecycle:
// resolved subdomains enqueue depth-capped children mid-scan. It asserts no
// panic (send on closed channel), clean completion, and that recursion expands
// the total beyond the initial entry count. Run under -race.
func TestRunRecursiveEnqueuesChildren(t *testing.T) {
	// hitRate 100 so every job resolves and spawns children, maximizing the
	// chance of catching a send-on-closed-channel race.
	cfg := Config{
		Domain:      "example.com",
		Entries:     []string{"www", "api", "dev"},
		Concurrency: 8,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     100,
		Attempts:    1,
		Recursive:   true,
		Depth:       3,
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)

	var done *Event
	results := 0
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			results++
		case EventDone:
			e := ev
			done = &e
		}
	}

	if done == nil {
		t.Fatal("no EventDone received")
	}
	// Initial 3 entries, each resolving and spawning 3 children to depth 3:
	// 3 + 3*3 + 3*3*3 = 39 unique jobs.
	if done.Total <= 3 {
		t.Errorf("expected recursion to expand total beyond initial 3, got %d", done.Total)
	}
	if done.Processed != done.Total {
		t.Errorf("Processed %d != Total %d", done.Processed, done.Total)
	}
	if int64(results) != done.Found {
		t.Errorf("result events %d != Found %d", results, done.Found)
	}
}

// TestRunRecursiveLoopProtection asserts the visited set prevents duplicate or
// cyclic work: with depth high and full resolution, the job count stays finite
// and equals the unique domain count.
func TestRunRecursiveLoopProtection(t *testing.T) {
	cfg := Config{
		Domain:      "example.com",
		Entries:     []string{"a", "b"},
		Concurrency: 4,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     100,
		Attempts:    1,
		Recursive:   true,
		Depth:       4,
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)

	var done *Event
	for ev := range events {
		if ev.Kind == EventDone {
			e := ev
			done = &e
		}
	}
	if done == nil {
		t.Fatal("no EventDone received")
	}
	// 2 entries to depth 4: 2 + 4 + 8 + 16 = 30 unique jobs.
	if done.Total != 30 {
		t.Errorf("expected 30 unique jobs, got %d", done.Total)
	}
	if done.Processed != done.Total {
		t.Errorf("Processed %d != Total %d", done.Processed, done.Total)
	}
}

// TestRunRateLimit asserts that -rate paces queries: N queries at R qps should
// take at least (N-1)/R seconds. Uses simulate mode so it is network-free.
func TestRunRateLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive rate limit test in short mode")
	}

	const queries = 20
	const rate = 10 // qps
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(queries),
		Concurrency: 8,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     50,
		Attempts:    1,
		Rate:        rate,
	}

	events := make(chan Event, 64)
	start := time.Now()
	go Run(context.Background(), cfg, events)
	for range events { //nolint:revive // draining
	}
	elapsed := time.Since(start)

	// Floor: the first tick fires after one interval, so expect at least
	// (queries-1)/rate seconds, with a margin for scheduling jitter.
	minExpected := time.Duration(float64(queries-1) / float64(rate) * 0.8 * float64(time.Second))
	if elapsed < minExpected {
		t.Errorf("rate-limited scan finished too fast: %s < %s", elapsed, minExpected)
	}
}

// TestRunContextCancel cancels mid-scan and asserts Run returns and closes the
// events channel promptly.
func TestRunContextCancel(t *testing.T) {
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(100000),
		Concurrency: 8,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     50,
		Attempts:    1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan Event, 64)
	go Run(ctx, cfg, events)

	// Consume a few events, then cancel.
	received := 0
	for ev := range events {
		received++
		if received == 1 || ev.Kind == EventProgress {
			cancel()
		}
		if received > 20 {
			cancel()
		}
	}

	// Reaching here means the channel was closed (Run returned) after cancel.
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("events channel still open after Run returned")
		}
	default:
	}
}

func collect(events <-chan Event) (done *Event, errs []Event, results int) {
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			results++
		case EventError:
			errs = append(errs, ev)
		case EventDone:
			e := ev
			done = &e
		}
	}
	return done, errs, results
}

func hookOutcome(o dns.Outcome) func(context.Context, string) ([]dns.Record, dns.Outcome) {
	return func(context.Context, string) ([]dns.Record, dns.Outcome) {
		if o == dns.OutcomeFound {
			return []dns.Record{{Type: "A", Value: "192.0.2.1"}}, o
		}
		return nil, o
	}
}

// TestRunCancelDoesNotCountFailures covers #42: lookups in flight when the scan
// is cancelled must not be counted as failures, so an interrupt can neither
// inflate the "other" bucket nor trip the reliability guard.
func TestRunCancelDoesNotCountFailures(t *testing.T) {
	const fast = reliabilityMinJobs + 50
	var n atomic.Int64
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(fast + 500),
		Concurrency: 100,
		Timeout:     time.Second,
		Simulate:    true,
		Attempts:    1,
		resolveHook: func(ctx context.Context, _ string) ([]dns.Record, dns.Outcome) {
			if n.Add(1) <= fast {
				return nil, dns.OutcomeNXDomain
			}
			// Block like a slow lookup, then fail the way an interrupted
			// net.Resolver call surfaces before classification.
			<-ctx.Done()
			return nil, dns.OutcomeOther
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan Event, 64)
	go Run(ctx, cfg, events)
	go func() {
		for n.Load() < fast+int64(cfg.Concurrency) {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	done, errs, _ := collect(events)

	if done == nil {
		t.Fatal("no EventDone received")
	}
	if len(errs) != 0 {
		t.Fatalf("cancellation produced an error event: %q", errs[0].Message)
	}
	if done.Stats.Other != 0 || done.Stats.Timeout != 0 || done.Stats.Refused != 0 {
		t.Fatalf("cancelled lookups counted as failures: %+v", done.Stats)
	}
	if done.Stats.Sum() != done.Processed {
		t.Errorf("stats sum %d != processed %d", done.Stats.Sum(), done.Processed)
	}
}

// TestRunStatsSumToProcessed injects a mix of classified outcomes in simulate
// mode and asserts every processed job is accounted for. Failure rate stays
// under the reliability threshold so the scan completes.
func TestRunStatsSumToProcessed(t *testing.T) {
	var n atomic.Int64
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(250),
		Concurrency: 8,
		Timeout:     time.Second,
		Simulate:    true,
		Attempts:    1,
		resolveHook: func(context.Context, string) ([]dns.Record, dns.Outcome) {
			switch n.Add(1) % 10 {
			case 0:
				return []dns.Record{{Type: "A", Value: "192.0.2.1"}}, dns.OutcomeFound
			case 1:
				return nil, dns.OutcomeTimeout
			default:
				return nil, dns.OutcomeNXDomain
			}
		},
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	done, errs, results := collect(events)

	if done == nil {
		t.Fatal("no EventDone received")
	}
	if len(errs) != 0 {
		t.Fatalf("reliability guard fired unexpectedly: %q", errs[0].Message)
	}
	if done.Processed != done.Total {
		t.Errorf("Processed %d != Total %d", done.Processed, done.Total)
	}
	if done.Stats.Sum() != done.Processed {
		t.Errorf("stats sum %d != processed %d: %+v", done.Stats.Sum(), done.Processed, done.Stats)
	}
	if done.Found != done.Stats.Found {
		t.Errorf("Found %d != Stats.Found %d", done.Found, done.Stats.Found)
	}
	if int64(results) != done.Found {
		t.Errorf("result events %d != Found %d", results, done.Found)
	}
	if done.Stats.Timeout == 0 {
		t.Error("expected some timeout outcomes from the hook")
	}
	if done.Stats.NXDomain == 0 {
		t.Error("expected some nxdomain outcomes from the hook")
	}
}

// TestRunReliabilityGuardAborts injects a high timeout rate and asserts the
// guard emits EventError, names the failure rate, and cancels the scan.
func TestRunReliabilityGuardAborts(t *testing.T) {
	n := reliabilityMinJobs + 50
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(n),
		Concurrency: 4,
		Timeout:     time.Second,
		Simulate:    true,
		Attempts:    1,
		Rate:        0,
		resolveHook: hookOutcome(dns.OutcomeTimeout),
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	done, errs, _ := collect(events)

	if len(errs) == 0 {
		t.Fatal("expected EventError from reliability guard")
	}
	msg := errs[0].Message
	if !strings.Contains(msg, "aborting scan") {
		t.Errorf("error message %q: want aborting scan", msg)
	}
	if !strings.Contains(msg, "timeout/refused/other") {
		t.Errorf("error message %q: want failure classes", msg)
	}
	if !strings.Contains(msg, "-t 4") || !strings.Contains(msg, "-rate 0") {
		t.Errorf("error message %q: want configured -t and -rate", msg)
	}
	if done == nil {
		t.Fatal("no EventDone received after abort")
	}
	if done.Stats.Sum() != done.Processed {
		t.Errorf("stats sum %d != processed %d: %+v", done.Stats.Sum(), done.Processed, done.Stats)
	}
	if done.Stats.Timeout == 0 {
		t.Error("expected timeout counter to be populated")
	}
}

// TestRunReliabilityGuardNoAbort keeps scanning after the warning.
func TestRunReliabilityGuardNoAbort(t *testing.T) {
	n := reliabilityMinJobs + 50
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(n),
		Concurrency: 8,
		Timeout:     time.Second,
		Simulate:    true,
		Attempts:    1,
		NoAbort:     true,
		resolveHook: hookOutcome(dns.OutcomeRefused),
	}

	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	done, errs, _ := collect(events)

	if len(errs) == 0 {
		t.Fatal("expected warning EventError from reliability guard")
	}
	if !strings.Contains(errs[0].Message, "warning") {
		t.Errorf("error message %q: want warning", errs[0].Message)
	}
	if done == nil {
		t.Fatal("no EventDone received")
	}
	if done.Processed != int64(n) {
		t.Errorf("NoAbort should finish all %d jobs, processed %d", n, done.Processed)
	}
	if done.Stats.Sum() != done.Processed {
		t.Errorf("stats sum %d != processed %d: %+v", done.Stats.Sum(), done.Processed, done.Stats)
	}
	if done.Stats.Refused != int64(n) {
		t.Errorf("Refused = %d, want %d", done.Stats.Refused, n)
	}
}

func TestRecursionCeiling(t *testing.T) {
	got := RecursionCeiling(10000, 3)
	if got < 1e12 {
		t.Fatalf("ceiling(10000,3) = %g, want >= 1e12", got)
	}
	if RecursionCeiling(0, 3) != 0 || RecursionCeiling(5, 0) != 0 {
		t.Fatal("empty inputs should be 0")
	}
	if RecursionCeiling(1, 4) != 4 {
		t.Fatalf("ceiling(1,4) = %g, want 4", RecursionCeiling(1, 4))
	}
}

func TestRunMaxQueriesStopsAdmission(t *testing.T) {
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(50),
		Concurrency: 4,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     0,
		Attempts:    1,
		MaxQueries:  10,
	}
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)

	var done *Event
	var capMsg string
	for ev := range events {
		switch ev.Kind {
		case EventNotice:
			if strings.Contains(ev.Message, "query cap reached") {
				capMsg = ev.Message
			}
		case EventDone:
			e := ev
			done = &e
		case EventError:
			t.Fatalf("unexpected error: %s", ev.Message)
		}
	}
	if done == nil {
		t.Fatal("no EventDone")
	}
	if done.Processed != 10 || done.Total != 10 {
		t.Errorf("Processed/Total = %d/%d, want 10/10", done.Processed, done.Total)
	}
	if capMsg == "" || !strings.Contains(capMsg, "skipped 40") {
		t.Errorf("cap event %q: want skipped 40", capMsg)
	}
}

func TestRunRecursionCeilingRefuse(t *testing.T) {
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(100),
		Concurrency: 1,
		Timeout:     time.Second,
		Simulate:    true,
		Attempts:    1,
		Recursive:   true,
		Depth:       4,
	}
	events := make(chan Event, 8)
	go Run(context.Background(), cfg, events)
	done, errs, _ := collect(events)
	if len(errs) == 0 {
		t.Fatal("expected refusal EventError")
	}
	if !strings.Contains(errs[0].Message, "refusing to start") {
		t.Errorf("message %q", errs[0].Message)
	}
	if done != nil {
		t.Error("refused scan should not emit EventDone")
	}
}

func TestRunRecursionCeilingForceAllows(t *testing.T) {
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(100),
		Concurrency: 4,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     0,
		Attempts:    1,
		Recursive:   true,
		Depth:       4,
		Force:       true,
	}
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	done, errs, _ := collect(events)
	if len(errs) != 0 {
		t.Fatalf("unexpected error: %s", errs[0].Message)
	}
	if done == nil {
		t.Fatal("no EventDone")
	}
	if done.Processed != 100 {
		t.Errorf("Processed = %d, want 100 (no expansion at hit-rate 0)", done.Processed)
	}
}

// TestRunInterruptDuringPreflightIsSilent: Ctrl+C while the preflight lookup is
// in flight must not be reported as a resolver failure.
func TestRunInterruptDuringPreflightIsSilent(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	addr := pc.LocalAddr().String()
	cfg := Config{
		Domain:      "example.com",
		Entries:     []string{"www"},
		Concurrency: 1,
		Timeout:     5 * time.Second, // the black hole never answers; cancel first
		Attempts:    1,
		Types:       []string{"A"},
		DNSServer:   addr,
		Resolver:    dns.NewResolver(5*time.Second, addr),
	}
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan Event, 8)
	go Run(ctx, cfg, events)
	time.AfterFunc(100*time.Millisecond, cancel)
	_, errs, _ := collect(events)
	if len(errs) != 0 {
		t.Fatalf("interrupt reported as error: %q", errs[0].Message)
	}
}

func TestRunPreflightFailsOnBlackHole(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	addr := pc.LocalAddr().String()
	timeout := 80 * time.Millisecond
	cfg := Config{
		Domain:      "example.com",
		Entries:     []string{"www"},
		Concurrency: 1,
		Timeout:     timeout,
		Attempts:    1,
		Types:       []string{"A"},
		DNSServer:   addr,
		Resolver:    dns.NewResolver(timeout, addr),
	}
	events := make(chan Event, 8)
	go Run(context.Background(), cfg, events)
	done, errs, _ := collect(events)
	if len(errs) == 0 {
		t.Fatal("expected preflight EventError")
	}
	if !strings.Contains(errs[0].Message, "preflight") || !strings.Contains(errs[0].Message, addr) {
		t.Errorf("message %q: want preflight and resolver addr", errs[0].Message)
	}
	if done != nil {
		t.Error("failed preflight should not emit EventDone")
	}
}

func TestFingerprintMatch(t *testing.T) {
	recs := []dns.Record{{Type: "A", Value: "192.0.2.99"}, {Type: "AAAA", Value: "::1"}}
	fp := newFingerprint(recs)
	if covered, _ := fp.match([]dns.Record{{Type: "A", Value: "192.0.2.99"}}); !covered {
		t.Error("A-only should be covered by an A+AAAA fingerprint")
	}
	if covered, overlaps := fp.match([]dns.Record{{Type: "A", Value: "192.0.2.1"}}); covered || overlaps {
		t.Error("different IP must not match")
	}
	if covered, overlaps := fp.match([]dns.Record{{Type: "A", Value: "192.0.2.99"}, {Type: "A", Value: "192.0.2.1"}}); covered || !overlaps {
		t.Error("partial match must be an overlap, not covered")
	}
	if covered, _ := newFingerprint(nil).match(recs); covered {
		t.Error("empty fingerprint must not filter")
	}
}

// TestRunRotatingPoolWildcardFiltered covers #48: a wildcard that answers
// from a rotating pool of 8 addresses is filtered under -force (at least 95%
// of wildcard names), and real names with their own addresses are all kept.
func TestRunRotatingPoolWildcardFiltered(t *testing.T) {
	var next atomic.Uint32
	real := map[string][4]byte{}
	var entries []string
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("real%d", i)
		entries = append(entries, name)
		real[name+".example.com"] = [4]byte{198, 51, 100, byte(i + 1)}
	}
	for i := 0; i < 50; i++ {
		entries = append(entries, fmt.Sprintf("w%d", i))
	}
	addr, stop := startUDPDNSAction(t, func(name string) dnsAction {
		if ip, ok := real[name]; ok {
			return dnsAction{ip: ip, hit: true}
		}
		if strings.HasSuffix(name, ".example.com") {
			n := next.Add(1)
			return dnsAction{ip: [4]byte{203, 0, 113, byte(n%8 + 1)}, hit: true}
		}
		return dnsAction{}
	})
	defer stop()

	cfg := Config{
		Domain:      "example.com",
		Entries:     entries,
		Concurrency: 4,
		Timeout:     time.Second,
		Attempts:    1,
		Force:       true,
		Types:       []string{"A"},
		Resolver:    dns.NewResolver(time.Second, addr),
		DNSServer:   addr,
	}
	events := make(chan Event, 256)
	go Run(context.Background(), cfg, events)
	found := map[string]bool{}
	var done *Event
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			found[ev.Domain] = true
		case EventDone:
			e := ev
			done = &e
		case EventError:
			t.Fatalf("unexpected error: %s", ev.Message)
		}
	}
	if done == nil {
		t.Fatal("no EventDone")
	}
	for name := range real {
		if !found[name] {
			t.Errorf("real name %s was filtered", name)
		}
	}
	leaked := len(found) - len(real)
	if filtered := 50 - leaked; filtered*100 < 50*95 {
		t.Errorf("filtered %d/50 rotating-pool wildcard answers, want >= 95%%; stats=%+v", filtered, done.Stats)
	}
}

func skipDNSName(msg []byte, off int) (int, bool) {
	for off < len(msg) {
		l := int(msg[off])
		if l == 0 {
			return off + 1, true
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return 0, false
			}
			return off + 2, true
		}
		off += 1 + l
	}
	return 0, false
}

func dnsQNameType(query []byte) (string, uint16, bool) {
	if len(query) < 12 {
		return "", 0, false
	}
	var labels []string
	off := 12
	for off < len(query) {
		l := int(query[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			return "", 0, false
		}
		if off+1+l > len(query) {
			return "", 0, false
		}
		labels = append(labels, string(query[off+1:off+1+l]))
		off += 1 + l
	}
	if off+2 > len(query) {
		return "", 0, false
	}
	qtype := uint16(query[off])<<8 | uint16(query[off+1])
	return strings.ToLower(strings.Join(labels, ".")), qtype, true
}

func dnsAResponse(query []byte, ip [4]byte) []byte {
	if len(query) < 12 {
		return nil
	}
	qend, ok := skipDNSName(query, 12)
	if !ok || qend+4 > len(query) {
		return nil
	}
	qend += 4
	flags := uint16(0x8400)
	if query[2]&0x01 != 0 {
		flags |= 0x0100
	}
	resp := make([]byte, 0, 64)
	resp = append(resp, query[0], query[1])
	resp = append(resp, byte(flags>>8), byte(flags))
	resp = append(resp, 0, 1, 0, 1, 0, 0, 0, 0)
	resp = append(resp, query[12:qend]...)
	resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ip[0], ip[1], ip[2], ip[3])
	return resp
}

func dnsNXDomain(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := append([]byte(nil), query...)
	resp[2] |= 0x80
	resp[3] = (resp[3] & 0xF0) | 0x03
	return resp
}

// dnsAction tells startUDPDNSAction how to answer one query.
type dnsAction struct {
	ip       [4]byte
	hit      bool // answer A with ip
	drop     bool // never answer (the client times out)
	servFail bool // answer SERVFAIL
}

func startUDPDNS(t *testing.T, handle func(name string, qtype uint16) ([4]byte, bool)) (addr string, stop func()) {
	t.Helper()
	return startUDPDNSAction(t, func(name string) dnsAction {
		ip, hit := handle(name, 1)
		return dnsAction{ip: ip, hit: hit}
	})
}

func startUDPDNSAction(t *testing.T, handle func(name string) dnsAction) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			name, qtype, ok := dnsQNameType(q)
			if !ok {
				continue
			}
			act := handle(name)
			var resp []byte
			switch {
			case act.drop:
			case act.servFail:
				resp = dnsNXDomain(q)
				resp[3] = (resp[3] & 0xF0) | 0x02
			case qtype == 1 && act.hit:
				resp = dnsAResponse(q, act.ip)
			default:
				resp = dnsNXDomain(q)
			}
			if resp != nil {
				_, _ = pc.WriteTo(resp, src)
			}
		}
	}()
	return pc.LocalAddr().String(), func() {
		_ = pc.Close()
		<-done
	}
}

func isProbeLabel(name, parent string) bool {
	suffix := "." + parent
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	label := strings.TrimSuffix(name, suffix)
	if strings.Contains(label, ".") || len(label) != 32 {
		return false
	}
	for _, c := range label {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func TestRunWildcardFingerprintFilters(t *testing.T) {
	wild := [4]byte{192, 0, 2, 99}
	addr, stop := startUDPDNS(t, func(string, uint16) ([4]byte, bool) {
		return wild, true
	})
	defer stop()

	cfg := Config{
		Domain:      "example.com",
		Entries:     []string{"www", "mail", "api"},
		Concurrency: 2,
		Timeout:     time.Second,
		Attempts:    1,
		Force:       true,
		Types:       []string{"A"},
		Resolver:    dns.NewResolver(time.Second, addr),
		DNSServer:   addr,
	}
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	done, errs, results := collect(events)

	if done == nil {
		t.Fatal("no EventDone")
	}
	for _, e := range errs {
		t.Fatalf("unexpected error: %s", e.Message)
	}
	if results != 0 {
		t.Errorf("result events = %d, want 0 (all wildcard-filtered)", results)
	}
	if done.Found != 0 {
		t.Errorf("Found = %d, want 0", done.Found)
	}
	if done.Stats.WildcardFiltered != 3 {
		t.Errorf("WildcardFiltered = %d, want 3; stats=%+v", done.Stats.WildcardFiltered, done.Stats)
	}
	if done.Stats.Sum() != done.Processed {
		t.Errorf("stats sum %d != processed %d", done.Stats.Sum(), done.Processed)
	}
}

func TestRunWildcardBranchSkipsExpansion(t *testing.T) {
	realIP := [4]byte{192, 0, 2, 1}
	wildIP := [4]byte{192, 0, 2, 99}
	addr, stop := startUDPDNS(t, func(name string, _ uint16) ([4]byte, bool) {
		switch {
		case name == "unique.example.com":
			return realIP, true
		case isProbeLabel(name, "unique.example.com"):
			return wildIP, true
		default:
			return [4]byte{}, false
		}
	})
	defer stop()

	cfg := Config{
		Domain:      "example.com",
		Entries:     []string{"unique", "www"},
		Concurrency: 2,
		Timeout:     time.Second,
		Attempts:    1,
		Types:       []string{"A"},
		Recursive:   true,
		Depth:       2,
		Resolver:    dns.NewResolver(time.Second, addr),
		DNSServer:   addr,
	}
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)

	var done *Event
	var wildMsgs []string
	results := 0
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			results++
		case EventNotice:
			wildMsgs = append(wildMsgs, ev.Message)
		case EventDone:
			e := ev
			done = &e
		case EventError:
			t.Fatalf("unexpected error: %s", ev.Message)
		}
	}
	if done == nil {
		t.Fatal("no EventDone")
	}
	if results != 1 || done.Found != 1 {
		t.Errorf("found results=%d Found=%d, want 1", results, done.Found)
	}
	if done.Total != 2 {
		t.Errorf("Total = %d, want 2 (wildcard branch must not expand)", done.Total)
	}
	skip := false
	for _, m := range wildMsgs {
		if strings.Contains(m, "unique.example.com") && strings.Contains(m, "skipping recursive expansion") {
			skip = true
		}
	}
	if !skip {
		t.Errorf("expected skip-expansion event, got %v", wildMsgs)
	}
}

// TestRunWildcardProbeFailureAtRoot covers #47 at the root: probes that time
// out or SERVFAIL abort the scan instead of reading as "no wildcard", and
// -force scans anyway with a warning.
func TestRunWildcardProbeFailureAtRoot(t *testing.T) {
	for _, tc := range []struct {
		name string
		act  dnsAction
	}{
		{"timeout", dnsAction{drop: true}},
		{"servfail", dnsAction{servFail: true}},
	} {
		for _, force := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/force=%v", tc.name, force), func(t *testing.T) {
				addr, stop := startUDPDNSAction(t, func(name string) dnsAction {
					switch {
					case name == "www.example.com":
						return dnsAction{ip: [4]byte{192, 0, 2, 1}, hit: true}
					case isProbeLabel(name, "example.com"):
						return tc.act
					}
					return dnsAction{}
				})
				defer stop()

				timeout := 100 * time.Millisecond
				cfg := Config{
					Domain:      "example.com",
					Entries:     []string{"www", "mail"},
					Concurrency: 2,
					Timeout:     timeout,
					Attempts:    2,
					Force:       force,
					Types:       []string{"A"},
					Resolver:    dns.NewResolver(timeout, addr),
					DNSServer:   addr,
				}
				events := make(chan Event, 64)
				go Run(context.Background(), cfg, events)
				var errs, notices []string
				results := 0
				for ev := range events {
					switch ev.Kind {
					case EventResult:
						results++
					case EventError:
						errs = append(errs, ev.Message)
					case EventNotice:
						notices = append(notices, ev.Message)
					}
				}

				if !force {
					if len(errs) != 1 || !strings.Contains(errs[0], "wildcard detection failed") {
						t.Fatalf("errors = %v, want one wildcard-detection failure", errs)
					}
					if results != 0 {
						t.Fatalf("results = %d, want 0 (scan must not start)", results)
					}
					return
				}
				if len(errs) != 0 {
					t.Fatalf("unexpected errors under -force: %v", errs)
				}
				if results != 1 {
					t.Fatalf("results = %d, want 1", results)
				}
				warned := false
				for _, m := range notices {
					warned = warned || strings.Contains(m, "without wildcard filtering")
				}
				if !warned {
					t.Fatalf("notices = %v, want a without-filtering warning", notices)
				}
			})
		}
	}
}

// TestRunWildcardProbeFailureInRecursion is the #47 repro: *.dev.example.com
// is a wildcard whose probe queries are dropped. The branch must be skipped,
// not expanded into one bogus result per wordlist entry.
func TestRunWildcardProbeFailureInRecursion(t *testing.T) {
	entries := []string{"dev"}
	for i := 0; i < 30; i++ {
		entries = append(entries, fmt.Sprintf("w%d", i))
	}
	addr, stop := startUDPDNSAction(t, func(name string) dnsAction {
		switch {
		case isProbeLabel(name, "dev.example.com"):
			return dnsAction{drop: true}
		case name == "dev.example.com", strings.HasSuffix(name, ".dev.example.com"):
			return dnsAction{ip: [4]byte{192, 0, 2, 7}, hit: true}
		}
		return dnsAction{}
	})
	defer stop()

	timeout := 100 * time.Millisecond
	cfg := Config{
		Domain:      "example.com",
		Entries:     entries,
		Concurrency: 4,
		Timeout:     timeout,
		Attempts:    1,
		Types:       []string{"A"},
		Recursive:   true,
		Depth:       2,
		Resolver:    dns.NewResolver(timeout, addr),
		DNSServer:   addr,
	}
	events := make(chan Event, 256)
	go Run(context.Background(), cfg, events)
	var notices []string
	results := 0
	for ev := range events {
		switch ev.Kind {
		case EventResult:
			results++
		case EventNotice:
			notices = append(notices, ev.Message)
		case EventError:
			t.Fatalf("unexpected error: %s", ev.Message)
		}
	}
	if results != 1 {
		t.Fatalf("results = %d, want 1 (dev only; the unverified branch must not expand)", results)
	}
	skipped := false
	for _, m := range notices {
		skipped = skipped || (strings.Contains(m, "dev.example.com") && strings.Contains(m, "wildcard check failed"))
	}
	if !skipped {
		t.Fatalf("notices = %v, want a skip notice for dev.example.com", notices)
	}
}

// TestRunMaxQueriesRecursiveCountsSkipped covers #51: once the cap is reached,
// children of found parents are counted as skipped without being built or
// recorded, and the totals stay exact.
func TestRunMaxQueriesRecursiveCountsSkipped(t *testing.T) {
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(1000),
		Concurrency: 8,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     100,
		Attempts:    1,
		Recursive:   true,
		Depth:       3,
		MaxQueries:  50,
	}
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)

	var done *Event
	var capMsg string
	for ev := range events {
		switch ev.Kind {
		case EventNotice:
			if strings.Contains(ev.Message, "query cap reached") {
				capMsg = ev.Message
			}
		case EventDone:
			e := ev
			done = &e
		case EventError:
			t.Fatalf("unexpected error: %s", ev.Message)
		}
	}
	if done == nil {
		t.Fatal("no EventDone")
	}
	if done.Processed != 50 || done.Total != 50 {
		t.Errorf("Processed/Total = %d/%d, want 50/50", done.Processed, done.Total)
	}
	// 950 unadmitted depth-1 names plus 1000 children for each of the 50
	// found parents.
	if want := "skipped 50950"; !strings.Contains(capMsg, want) {
		t.Errorf("cap event %q: want %q", capMsg, want)
	}
}

// BenchmarkRun1M guards against dispatcher overhead growing faster than
// linearly with wordlist size (#49).
func BenchmarkRun1M(b *testing.B) {
	entries := makeEntries(1_000_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg := Config{
			Domain:      "example.com",
			Entries:     entries,
			Concurrency: 50,
			Timeout:     time.Second,
			Simulate:    true,
			HitRate:     0,
			Attempts:    1,
		}
		events := make(chan Event, 64)
		go Run(context.Background(), cfg, events)
		for range events {
		}
	}
}

// TestRunPreflightRetries covers #57: a dropped first preflight query fails a
// one-attempt scan but not one with -attempts 2.
func TestRunPreflightRetries(t *testing.T) {
	for _, attempts := range []int{1, 2} {
		t.Run(fmt.Sprintf("attempts=%d", attempts), func(t *testing.T) {
			var apexQueries atomic.Int32
			addr, stop := startUDPDNSAction(t, func(name string) dnsAction {
				if name == "example.com" && apexQueries.Add(1) == 1 {
					return dnsAction{drop: true}
				}
				return dnsAction{}
			})
			defer stop()

			timeout := 150 * time.Millisecond
			cfg := Config{
				Domain:      "example.com",
				Entries:     []string{"www"},
				Concurrency: 1,
				Timeout:     timeout,
				Attempts:    attempts,
				Types:       []string{"A"},
				Resolver:    dns.NewResolver(timeout, addr),
				DNSServer:   addr,
			}
			events := make(chan Event, 16)
			go Run(context.Background(), cfg, events)
			done, errs, _ := collect(events)

			if attempts == 1 {
				if len(errs) != 1 || !strings.Contains(errs[0].Message, "failed preflight") {
					t.Fatalf("errors = %v, want a preflight failure", errs)
				}
				return
			}
			if len(errs) != 0 {
				t.Fatalf("unexpected errors: %v", errs)
			}
			if done == nil || done.Processed != 1 {
				t.Fatalf("done = %+v, want one processed job", done)
			}
		})
	}
}

// TestWorkerCountCapped covers #58: a huge -t never spawns more workers than
// the scan has jobs.
func TestWorkerCountCapped(t *testing.T) {
	for _, tc := range []struct {
		cfg   Config
		depth int
		want  int
	}{
		{Config{Concurrency: 5_000_000, Entries: makeEntries(8)}, 1, 8},
		{Config{Concurrency: 100, Entries: makeEntries(8), Recursive: true}, 2, 72},
		{Config{Concurrency: 100, Entries: makeEntries(1000), MaxQueries: 10}, 1, 10},
		{Config{Concurrency: 4, Entries: makeEntries(1000)}, 1, 4},
		{Config{Concurrency: 4}, 1, 1},
	} {
		if got := workerCount(tc.cfg, tc.depth); got != tc.want {
			t.Errorf("workerCount(t=%d, n=%d, rec=%v, depth=%d, max=%d) = %d, want %d",
				tc.cfg.Concurrency, len(tc.cfg.Entries), tc.cfg.Recursive, tc.depth, tc.cfg.MaxQueries, got, tc.want)
		}
	}
}

// TestNoticesCarryKind covers #68: notices are machine-readable by kind.
func TestNoticesCarryKind(t *testing.T) {
	cfg := Config{
		Domain:      "example.com",
		Entries:     makeEntries(20),
		Concurrency: 2,
		Timeout:     time.Second,
		Simulate:    true,
		HitRate:     100,
		Attempts:    1,
		Recursive:   true,
		Depth:       2,
		MaxQueries:  5,
	}
	events := make(chan Event, 64)
	go Run(context.Background(), cfg, events)
	kinds := map[NoticeKind]bool{}
	for ev := range events {
		if ev.Kind == EventNotice {
			kinds[ev.Notice] = true
		}
	}
	for _, k := range []NoticeKind{NoticeCeiling, NoticeCap} {
		if !kinds[k] {
			t.Errorf("no %s notice; got %v", k, kinds)
		}
	}
}
