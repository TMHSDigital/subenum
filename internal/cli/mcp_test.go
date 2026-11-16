package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"github.com/TMHSDigital/subenum/internal/labzone"
	"github.com/TMHSDigital/subenum/internal/mcp"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/report"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/wordlist"
	"github.com/TMHSDigital/subenum/pkg/subenum"
)

// mcpCall is one tools/call request for runMCPSession.
type mcpCall struct {
	tool string
	args string // JSON object
}

// runMCPSession runs `subenum mcp args...` over a scripted session: it
// initializes, lists the tools, makes each call, and returns the tool names
// and every call's reply by position. The server answers everything it read
// before returning, so a fixed input works.
func runMCPSession(t *testing.T, args []string, calls ...mcpCall) (tools []string, replies []map[string]any) {
	t.Helper()
	var in strings.Builder
	in.WriteString(`{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-06-18"}}` + "\n")
	in.WriteString(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	in.WriteString(`{"jsonrpc":"2.0","id":"list","method":"tools/list"}` + "\n")
	for i, c := range calls {
		fmt.Fprintf(&in, `{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`+"\n", i, c.tool, c.args)
	}
	var stdout, stderr bytes.Buffer
	code := runWith(runArgs{args: append([]string{"mcp"}, args...), stdin: strings.NewReader(in.String()), stdout: &stdout, stderr: &stderr})
	if code != exitOK {
		t.Fatalf("mcp exited %d: %s", code, stderr.String())
	}
	replies = make([]map[string]any, len(calls))
	for line := range strings.SplitSeq(strings.TrimSpace(stdout.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stdout carries a non-JSON line %q", line)
		}
		switch id := m["id"].(type) {
		case string:
			if id == "list" {
				for _, tool := range m["result"].(map[string]any)["tools"].([]any) {
					tools = append(tools, tool.(map[string]any)["name"].(string))
				}
			}
		case float64:
			replies[int(id)] = m
		}
	}
	return tools, replies
}

// toolText returns a tools/call reply's text and isError.
func toolText(t *testing.T, reply map[string]any) (string, bool) {
	t.Helper()
	r, ok := reply["result"].(map[string]any)
	if !ok {
		t.Fatalf("not a tool result: %v", reply)
	}
	return r["content"].([]any)[0].(map[string]any)["text"].(string), r["isError"].(bool)
}

func mcpReportOf(t *testing.T, reply map[string]any) mcpReport {
	t.Helper()
	text, isErr := toolText(t, reply)
	var r mcpReport
	if err := json.Unmarshal([]byte(text), &r); err != nil {
		t.Fatalf("not a scan report (isError %v): %s", isErr, text)
	}
	return r
}

func reportNames(r mcpReport) []string {
	var names []string
	for _, res := range r.Results {
		names = append(names, strings.TrimSuffix(res.Name, ".lab.example"))
	}
	slices.Sort(names)
	return names
}

// TestE2EMCPLabScan runs lab_scan against the compiled-in scenarios (#131).
func TestE2EMCPLabScan(t *testing.T) {
	t.Parallel()
	tools, replies := runMCPSession(t, []string{"-max-queries", "100"},
		mcpCall{"lab_scan", `{"types": ["A", "AAAA", "CNAME"]}`},
		mcpCall{"lab_scan", `{"scenario": "lab2-wildcard"}`},
		mcpCall{"lab_scan", `{"scenario": "lab2-wildcard", "force": true}`},
		mcpCall{"lab_scan", `{"words": ["www", "mail", "nope", "vpn"], "max_queries": 2}`},
		mcpCall{"lab_scan", `{"max_queries": 101}`},
		mcpCall{"lab_scan", `{"scenario": "../../main"}`},
		mcpCall{"lab_scan", `{"resolver": "203.0.113.1"}`},
		mcpCall{"scan", `{"domain": "lab.example"}`},
	)
	if want := []string{"lab_scan", "explain_stats", "diff"}; !slices.Equal(tools, want) {
		t.Errorf("tools without -allow = %v, want %v", tools, want)
	}

	r := mcpReportOf(t, replies[0])
	if want := []string{"blog", "jenkins", "mail", "shop", "vpn", "www"}; !slices.Equal(reportNames(r), want) || r.Verdict != "complete" {
		t.Errorf("lab1: names %v verdict %s (%s), want %v complete", reportNames(r), r.Verdict, r.Reason, want)
	}

	if r := mcpReportOf(t, replies[1]); r.Verdict != verdictNotRun || r.Error == "" || r.Found != 0 {
		t.Errorf("lab2 without force: %+v, want not_run with an error", r)
	}
	if _, isErr := toolText(t, replies[1]); !isErr {
		t.Error("lab2 without force is not an error result")
	}
	if r := mcpReportOf(t, replies[2]); !r.Wildcard || r.Outcomes.WildcardFiltered == 0 || r.Error != "" {
		t.Errorf("lab2 with force: %+v, want wildcard results filtered", r)
	}

	r = mcpReportOf(t, replies[3])
	if r.MaxQueries != 2 || r.Skipped != 2 || r.Verdict != "degraded" {
		t.Errorf("max_queries 2: %+v, want 2 skipped and degraded", r)
	}

	for i, want := range map[int]string{4: "above the operator's cap of 100", 5: "unknown scenario", 6: `unknown field "resolver"`} {
		if text, isErr := toolText(t, replies[i]); !isErr || !strings.Contains(text, want) {
			t.Errorf("call %d: %q (isError %v), want an error containing %q", i, text, isErr, want)
		}
	}
	if e, ok := replies[7]["error"].(map[string]any); !ok || !strings.Contains(e["message"].(string), "unknown tool") {
		t.Errorf("scan without -allow: %v, want an unknown tool error", replies[7])
	}
}

// TestE2EMCPScanAllowList checks that scan enumerates only allow-listed
// domains, through the operator's resolver and within the operator's cap.
func TestE2EMCPScanAllowList(t *testing.T) {
	t.Parallel()
	zone, err := labzone.Load(filepath.Join("examples", "labs", "lab1-first-scan.zone"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := dnsserver.Listen(dnsserver.Options{}, zone.Handler([]string{"lab.example"}))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	tools, replies := runMCPSession(t,
		[]string{"-allow", "LAB.example., other.test", "-dns-server", srv.Addr, "-rate", "1000", "-max-queries", "3", "-timeout", "5000"},
		mcpCall{"scan", `{"domain": "https://lab.example/", "words": ["www", "mail", "nope"]}`},
		mcpCall{"scan", `{"domain": "lab.example", "words": ["www", "mail", "nope", "vpn"]}`},
		mcpCall{"scan", `{"domain": "notlab.example"}`},
		mcpCall{"scan", `{"domain": "lab.example.evil.test"}`},
		mcpCall{"scan", `{"domain": "lab.example", "max_queries": 4}`},
		mcpCall{"scan", `{"domain": "lab.example", "dns_server": "203.0.113.1"}`},
	)
	if want := []string{"lab_scan", "scan", "explain_stats", "diff"}; !slices.Equal(tools, want) {
		t.Errorf("tools = %v, want %v", tools, want)
	}
	if r := mcpReportOf(t, replies[0]); !slices.Equal(reportNames(r), []string{"mail", "www"}) || r.Verdict != "complete" || r.Rate != 1000 {
		t.Errorf("allowed scan: %+v", r)
	}
	if r := mcpReportOf(t, replies[1]); r.Skipped != 1 || r.MaxQueries != 3 {
		t.Errorf("the operator's cap of 3 was not enforced: %+v", r)
	}
	for i, want := range map[int]string{
		2: "notlab.example is not in the operator's allow-list",
		3: "lab.example.evil.test is not in the operator's allow-list",
		4: "above the operator's cap of 3",
		5: `unknown field "dns_server"`,
	} {
		if text, isErr := toolText(t, replies[i]); !isErr || !strings.Contains(text, want) {
			t.Errorf("call %d: %q (isError %v), want an error containing %q", i, text, isErr, want)
		}
	}
}

// TestE2EMCPScanOffset covers #313: a report whose max_queries left words
// untested gives next_offset, and a call with that offset tests the words
// after them, so an agent can work through a list longer than the cap.
func TestE2EMCPScanOffset(t *testing.T) {
	t.Parallel()
	const words = `"words": ["www", "mail", "nope", "vpn", "WWW", "shop"]`
	_, replies := runMCPSession(t, []string{"-max-queries", "100"},
		mcpCall{"lab_scan", `{` + words + `, "max_queries": 2}`},
		mcpCall{"lab_scan", `{` + words + `, "max_queries": 2, "offset": 2}`},
		mcpCall{"lab_scan", `{` + words + `, "max_queries": 2, "offset": 4}`},
		mcpCall{"lab_scan", `{` + words + `, "max_queries": 2, "exclude": ["mail.lab.example", "vpn.lab.example"]}`},
		mcpCall{"lab_scan", `{` + words + `, "offset": 5}`},
		mcpCall{"lab_scan", `{` + words + `, "offset": -1}`},
	)
	for i, want := range []struct {
		names []string
		next  int
	}{
		{[]string{"mail", "www"}, 2},
		{[]string{"vpn"}, 4},
		{[]string{"shop"}, 0}, // the repeated www is not a candidate: 5 in all
		{[]string{"www"}, 4},  // www and nope tested; mail and vpn are out of scope
	} {
		r := mcpReportOf(t, replies[i])
		if !slices.Equal(reportNames(r), want.names) || r.NextOffset != want.next {
			t.Errorf("call %d: names %v, next_offset %d; want %v, %d (%+v)", i, reportNames(r), r.NextOffset, want.names, want.next, r)
		}
		if named := strings.Contains(r.Reason, fmt.Sprintf("offset %d", want.next)); named != (want.next > 0) {
			t.Errorf("call %d: reason %q, next_offset %d", i, r.Reason, want.next)
		}
		if (r.Verdict == "complete") != (want.next == 0) {
			t.Errorf("call %d: verdict %s with next_offset %d", i, r.Verdict, want.next)
		}
	}
	for i, want := range map[int]string{4: "offset 5 is past the end of the word list, which has 5 candidates", 5: "offset must be 0 or more"} {
		if text, isErr := toolText(t, replies[i]); !isErr || !strings.Contains(text, want) {
			t.Errorf("call %d: %q (isError %v), want an error containing %q", i, text, isErr, want)
		}
	}

	// The default list, a few names per call: following next_offset tests
	// every word once and finds what one uncapped scan finds.
	var found []string
	var tested int64
	for offset, calls := 0, 0; ; calls++ {
		if calls > len(labWords()) {
			t.Fatalf("next_offset did not reach the end of the list after %d calls", calls)
		}
		_, replies := runMCPSession(t, nil, mcpCall{"lab_scan", fmt.Sprintf(`{"max_queries": 7, "offset": %d}`, offset)})
		r := mcpReportOf(t, replies[0])
		found = append(found, reportNames(r)...)
		tested += int64(r.Found) + r.Outcomes.NXDomain
		if r.NextOffset == 0 {
			if r.Verdict != "complete" {
				t.Errorf("last call at offset %d: %s (%s), want complete", offset, r.Verdict, r.Reason)
			}
			break
		}
		if r.NextOffset != offset+7 {
			t.Fatalf("offset %d: next_offset %d, want %d", offset, r.NextOffset, offset+7)
		}
		offset = r.NextOffset
	}
	slices.Sort(found)
	entries, _, _ := wordlist.Build(labWords(), labDomain)
	if want := []string{"jenkins", "mail", "shop", "vpn", "www"}; !slices.Equal(found, want) || tested != int64(len(entries)) {
		t.Errorf("following next_offset: found %v after testing %d names, want %v and %d", found, tested, want, len(entries))
	}
}

// TestE2EMCPScanOffsetLive checks offset on the scan tool, whose default is
// the bundled list and whose cap is the operator's (#313).
func TestE2EMCPScanOffsetLive(t *testing.T) {
	t.Parallel()
	zone, err := labzone.Load(filepath.Join("examples", "labs", "lab1-first-scan.zone"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := dnsserver.Listen(dnsserver.Options{}, zone.Handler([]string{"lab.example"}))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	bundled, _, _ := wordlist.Build(subenum.DefaultWords(), "lab.example")
	_, replies := runMCPSession(t,
		[]string{"-allow", "lab.example", "-dns-server", srv.Addr, "-rate", "1000", "-max-queries", "3", "-timeout", "5000"},
		mcpCall{"scan", `{"domain": "lab.example", "words": ["www", "mail", "nope", "vpn"]}`},
		mcpCall{"scan", `{"domain": "lab.example", "words": ["www", "mail", "nope", "vpn"], "offset": 3}`},
		mcpCall{"scan", `{"domain": "lab.example"}`},
		mcpCall{"scan", fmt.Sprintf(`{"domain": "lab.example", "offset": %d}`, len(bundled)-2)},
		mcpCall{"scan", fmt.Sprintf(`{"domain": "lab.example", "offset": %d}`, len(bundled))},
	)
	if r := mcpReportOf(t, replies[0]); r.NextOffset != 3 || r.Skipped != 1 {
		t.Errorf("capped scan: next_offset %d, skipped %d; want 3 and 1", r.NextOffset, r.Skipped)
	}
	if r := mcpReportOf(t, replies[1]); r.NextOffset != 0 || r.Verdict != "complete" || !slices.Equal(reportNames(r), []string{"vpn"}) {
		t.Errorf("scan at offset 3: %+v, want vpn and complete", r)
	}
	if r := mcpReportOf(t, replies[2]); r.NextOffset != 3 || r.Skipped != int64(len(bundled)-3) {
		t.Errorf("bundled list: next_offset %d, skipped %d; want 3 and %d", r.NextOffset, r.Skipped, len(bundled)-3)
	}
	if r := mcpReportOf(t, replies[3]); r.NextOffset != 0 || r.Verdict != "complete" || r.Found+int(r.Outcomes.NXDomain) != 2 {
		t.Errorf("the bundled list's last two words: %+v, want 2 tested and complete", r)
	}
	if text, isErr := toolText(t, replies[4]); !isErr || !strings.Contains(text, "past the end of the word list") {
		t.Errorf("offset at the end of the bundled list: %q (isError %v)", text, isErr)
	}
}

// TestMCPNextOffset: next_offset is given only when max_queries stopped the
// scan among the words and every admitted name was tested (#313).
func TestMCPNextOffset(t *testing.T) {
	cfg := subenum.Config{Domain: "lab.example", Words: []string{"a", "b", "c", "d"}, MaxQueries: 2}
	for _, tc := range []struct {
		name    string
		words   []string
		exclude []string
		stats   subenum.Stats
		want    int
	}{
		{name: "capped", stats: subenum.Stats{NXDomain: 2, Skipped: 2}, want: 12},
		{name: "nothing skipped", stats: subenum.Stats{NXDomain: 2}},
		{name: "stopped by the time budget", stats: subenum.Stats{NXDomain: 1, Skipped: 3, Expired: true}},
		{name: "admitted names left untested", stats: subenum.Stats{NXDomain: 1, Skipped: 3}},
		{name: "words all tested, a source's names skipped", words: []string{"a", "b"}, stats: subenum.Stats{NXDomain: 2, Skipped: 5}},
		{name: "exclusions passed over", exclude: []string{"b.lab.example"}, stats: subenum.Stats{NXDomain: 2, Skipped: 1, Excluded: 1}, want: 13},
		{name: "only excluded words left", exclude: []string{"c.lab.example", "*.d.lab.example", "d.lab.example"}, stats: subenum.Stats{NXDomain: 2, Skipped: 5, Excluded: 2}},
	} {
		c := cfg
		if tc.words != nil {
			c.Words = tc.words
		}
		c.Exclude = tc.exclude
		if got := nextOffset(c, tc.stats, 10); got != tc.want {
			t.Errorf("%s: next offset %d, want %d", tc.name, got, tc.want)
		}
	}
}

// fakeSource is a passive source for tests: it returns names, or err.
type fakeSource struct {
	names []string
	err   error
}

func (f fakeSource) Names(context.Context, string) ([]string, error) { return f.names, f.err }

// TestE2EMCPScanSources checks that scan seeds candidates from the passive
// sources the operator enabled and only those, reporting each one (#268).
func TestE2EMCPScanSources(t *testing.T) {
	// This test replaces the process-wide source registry. Keep it serial so
	// parallel MCP sessions cannot read the stub or race with its restoration.
	zone, err := labzone.Load(filepath.Join("examples", "labs", "lab1-first-scan.zone"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := dnsserver.Listen(dnsserver.Options{}, zone.Handler([]string{"lab.example"}))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	saved := mcpSources
	t.Cleanup(func() { mcpSources = saved })
	mcpSources = map[string]func() subenum.Source{
		"ct":      func() subenum.Source { return fakeSource{names: []string{"vpn", "www"}} },
		"wayback": func() subenum.Source { return fakeSource{err: errors.New("503 from the archive")} },
	}

	base := []string{"-allow", "lab.example", "-dns-server", srv.Addr, "-rate", "1000", "-timeout", "5000"}
	_, replies := runMCPSession(t, append(base, "-sources", "ct,wayback"),
		mcpCall{"scan", `{"domain": "lab.example", "words": ["www"], "sources": ["ct", "wayback"]}`},
		mcpCall{"scan", `{"domain": "lab.example", "words": ["www"]}`},
		mcpCall{"scan", `{"domain": "lab.example", "sources": ["dns"]}`},
	)
	r := mcpReportOf(t, replies[0])
	if want := []string{"vpn", "www"}; !slices.Equal(reportNames(r), want) {
		t.Errorf("with sources: names %v, want %v", reportNames(r), want)
	}
	if len(r.Sources) != 2 || r.Sources[0] != (mcpSource{Name: "ct", Names: 2}) ||
		r.Sources[1].Name != "wayback" || !strings.Contains(r.Sources[1].Error, "503") {
		t.Errorf("sources report = %+v", r.Sources)
	}
	if r := mcpReportOf(t, replies[1]); len(r.Sources) != 0 || !slices.Equal(reportNames(r), []string{"www"}) {
		t.Errorf("a call without sources used them: %+v", r)
	}
	if text, isErr := toolText(t, replies[2]); !isErr || !strings.Contains(text, `source "dns" is not enabled`) {
		t.Errorf("unknown source: %q (isError %v)", text, isErr)
	}

	_, replies = runMCPSession(t, base, mcpCall{"scan", `{"domain": "lab.example", "sources": ["ct"]}`})
	if text, isErr := toolText(t, replies[0]); !isErr || !strings.Contains(text, "sources are off") {
		t.Errorf("sources without -sources: %q (isError %v)", text, isErr)
	}
}

// TestE2EMCPRemediationArgs covers #269: depth recurses, exclude keeps names
// out, retry_inconclusive retries the failed lookups, and the limits hold.
func TestE2EMCPRemediationArgs(t *testing.T) {
	t.Parallel()
	_, replies := runMCPSession(t, []string{"-max-queries", "500"},
		mcpCall{"lab_scan", `{"scenario": "lab4-recursive", "words": ["www", "dev", "api", "git", "corp", "vpn"], "depth": 2, "exclude": ["*.corp.lab.example"]}`},
		mcpCall{"lab_scan", `{"scenario": "lab5-failures", "words": ["www", "backup", "beta"], "retry_inconclusive": true, "auto_rate": true}`},
		mcpCall{"lab_scan", `{"depth": 4}`},
		mcpCall{"lab_scan", `{"exclude": ` + string(must(json.Marshal(make([]string, maxMCPExclude+1)))) + `}`},
	)
	r := mcpReportOf(t, replies[0])
	if want := []string{"api.dev", "corp", "dev", "git.dev", "www"}; !slices.Equal(reportNames(r), want) {
		t.Errorf("depth 2 with corp's branch excluded: %v, want %v", reportNames(r), want)
	}
	if r.Excluded == 0 {
		t.Errorf("excluded names not counted: %+v", r)
	}
	if r := mcpReportOf(t, replies[1]); r.Retried != 2 || r.Verdict == "complete" {
		t.Errorf("retry_inconclusive on lab5: retried %d, verdict %s; want 2 retried, still not complete", r.Retried, r.Verdict)
	}
	for i, want := range map[int]string{2: "depth must be 1 to 3", 3: "exclude has"} {
		if text, isErr := toolText(t, replies[i]); !isErr || !strings.Contains(text, want) {
			t.Errorf("call %d: %q (isError %v), want an error containing %q", i, text, isErr, want)
		}
	}
}

// must returns v, failing on err; for building test inputs.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// TestE2EMCPArgumentErrors covers the tool-argument checks the allow-list
// test does not (#258): each bad call is an isError result, and the server
// keeps answering after a scan that could not start.
func TestE2EMCPArgumentErrors(t *testing.T) {
	t.Parallel()
	tooMany, _ := json.Marshal(make([]string, maxMCPWords+1))
	_, replies := runMCPSession(t, []string{"-allow", "lab.example", "-dns-server", "127.0.0.1:9", "-max-queries", "10"},
		mcpCall{"lab_scan", `{"rate": -1}`},
		mcpCall{"lab_scan", `{"rate": 1001}`},
		mcpCall{"scan", `{"domain": "lab.example", "words": ` + string(tooMany) + `}`},
		mcpCall{"scan", `{"domain": "exa mple.com"}`},
		mcpCall{"scan", `{"domain": ""}`},
		mcpCall{"scan", `{"domain": "lab.example", "max_queries": -1}`},
		mcpCall{"scan", `{"domain": "lab.example", "words": ["!!!", "-"]}`},
		mcpCall{"lab_scan", `{"words": ["www"]}`},
	)
	for i, want := range []string{
		"rate must be 0 to 1000",
		"rate must be 0 to 1000",
		fmt.Sprintf("at most %d", maxMCPWords),
		"domain:",
		"domain:",
		"max_queries must be at least 1",
		"did not start",
	} {
		if text, isErr := toolText(t, replies[i]); !isErr || !strings.Contains(text, want) {
			t.Errorf("call %d: %q (isError %v), want an error containing %q", i, text, isErr, want)
		}
	}
	if r := mcpReportOf(t, replies[6]); r.Verdict != verdictNotRun || r.Error == "" {
		t.Errorf("unstartable scan: %+v, want not_run with an error", r)
	}
	if r := mcpReportOf(t, replies[7]); r.Verdict != "complete" || !slices.Equal(reportNames(r), []string{"www"}) {
		t.Errorf("the call after a failed one: %+v, want www and complete", r)
	}
}

// TestMCPExplainStatsBranches feeds explain_stats a report with every
// optional part set, so each explanation it can give is checked (#258).
func TestMCPExplainStatsBranches(t *testing.T) {
	s := output.Summary{
		Type: "summary", Verdict: "unreliable", Reason: "too many failures", Zone: "lab5-flaky",
		Resolver: "127.0.0.1:5353", QueriesSent: 300, DurationMs: 3000, AchievedQPS: 100, RateLimit: 50,
		Targets: []output.TargetSummary{{
			Domain: "lab.example", Status: "ok", Verdict: "unreliable", Reason: "too many failures",
			Processed: 90, Total: 100, Found: 4, SkippedCap: 10, StoppedBy: "duration", Wildcard: true,
			Outcomes: output.Outcomes{Resolved: 4, NXDomain: 50, Timeout: 30, Refused: 3, Other: 3, WildcardFiltered: 7},
			Takeover: 2, Internal: 1, AXFRAllowed: []string{"ns1.lab.example"}, ZoneDenial: "nsec",
			Sources:     []output.SourceSummary{{Name: "wayback", Error: "503"}},
			Permutation: &output.PermutationSummary{Seeds: 4, Candidates: 40, Found: 1},
			Error:       "resolver stopped answering",
		}, {
			// The permutation pass set this target's verdict (#298, #348).
			Domain: "two.example", Status: "ok", Verdict: "unreliable", Reason: "permutation pass: 30 of 60 lookups failed",
			Processed: 10, Total: 10, Outcomes: output.Outcomes{NXDomain: 10},
			Permutation: &output.PermutationSummary{Seeds: 2, Candidates: 60, Found: 0, Processed: 60, QueriesSent: 70, Verdict: "unreliable"},
		}},
		Diff: &output.DiffSummary{Previous: "prev.jsonl", Added: 1, Removed: 2, Unverified: 3},
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	quote, _ := json.Marshal(string(data))
	_, replies := runMCPSession(t, nil, mcpCall{"explain_stats", `{"stats": ` + string(quote) + `}`})
	text, isErr := toolText(t, replies[0])
	if isErr {
		t.Fatalf("explain_stats failed: %s", text)
	}
	for _, want := range []string{
		"Overall verdict: unreliable", "too many lookups failed", "lab run", "a limit of 50 per second",
		"Error: resolver stopped answering", "Next time: lower -rate", "because -max-duration ran out", "subenum -resume",
		"(a wildcard)", "2 results have a subdomain-takeover hint", "1 public names answer with internal",
		"Zone transfer (AXFR) was allowed by ns1.lab.example", "plain NSEC", "Passive source wayback failed (503)",
		"Permutation pass: 40 candidates from 4 seeds, 1 found", "Compared with prev.jsonl: 1 added, 2 removed",
		"3 earlier names could not be checked",
		"Permutation pass: 60 candidates from 2 seeds, 60 tested with 70 queries, 0 found; its own verdict unreliable",
		"The permutation pass set this target's verdict",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("explanation lacks %q:\n%s", want, text)
		}
	}
	if n := strings.Count(text, "The permutation pass set"); n != 1 {
		t.Errorf("%d targets said the permutation pass set their verdict, want only two.example:\n%s", n, text)
	}
}

// TestMCPVerdictMatchesReport is #263's drift guard: for the same finished
// scan the agent gets the verdict the CLI's run-quality report gives, except
// for the two cases the MCP report covers without a status field.
func TestMCPVerdictMatchesReport(t *testing.T) {
	type counts struct {
		found, nx, timeout, skipped int64
		expired, aborted, wildcard  bool
	}
	for _, tc := range []struct {
		name        string
		c           counts
		errMsg      string
		interrupted bool
		want        string // "" = the report's verdict
	}{
		{name: "complete", c: counts{found: 2, nx: 8}},
		{name: "query cap", c: counts{nx: 8, skipped: 2}},
		{name: "time cap", c: counts{nx: 8, skipped: 2, expired: true}},
		{name: "failures", c: counts{nx: 1, timeout: 9}},
		{name: "aborted", c: counts{nx: 3, timeout: 7, aborted: true}},
		{name: "wildcard", c: counts{found: 1, nx: 9, wildcard: true}},
		{name: "interrupted", c: counts{nx: 5}, interrupted: true},
		{name: "cancelled before testing", interrupted: true, want: verdictNotRun},
		{name: "error before testing", errMsg: "wildcard zone", want: verdictNotRun},
		{name: "error after a complete scan", c: counts{nx: 10}, errMsg: "boom", want: "unreliable"},
	} {
		c := tc.c
		pub := subenum.Stats{Found: c.found, NXDomain: c.nx, Timeout: c.timeout, Skipped: c.skipped, Expired: c.expired, Aborted: c.aborted, Wildcard: c.wildcard}
		eng := scan.Stats{Found: c.found, NXDomain: c.nx, Timeout: c.timeout, Skipped: c.skipped, Expired: c.expired, Aborted: c.aborted, Wildcard: c.wildcard}
		status := report.StatusOK
		if tc.interrupted {
			status = report.StatusInterrupted
		}
		rep := report.Target("x.example", status, "", true, scan.Event{Kind: scan.EventDone, Stats: eng}, scan.FieldName)
		want := tc.want
		if want == "" {
			want = rep.Verdict
		}
		got, reason := mcpVerdict(pub, tc.errMsg, tc.interrupted)
		if got != want {
			t.Errorf("%s: MCP verdict %s (%s), want %s (report: %s, %s)", tc.name, got, reason, want, rep.Verdict, rep.Reason)
		}
		if strings.ContainsAny(reason, "{}") || strings.Contains(reason, "MaxDuration") || strings.Contains(reason, "MaxQueries") {
			t.Errorf("%s: reason %q names a setting the agent does not know", tc.name, reason)
		}
	}
}

// TestMCPReportSchemaCoversTheReport is #270's drift guard: every JSON field
// of the report, and of its nested results, outcomes and sources, is in
// the outputSchema, and the schema names nothing the report lacks.
func TestMCPReportSchemaCoversTheReport(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(mcpReportSchema, &schema); err != nil {
		t.Fatalf("outputSchema is not JSON: %v", err)
	}
	props := func(s map[string]any) map[string]any { return s["properties"].(map[string]any) }
	top := props(schema)
	check := func(where string, typ reflect.Type, schemaProps map[string]any) {
		t.Helper()
		fields := map[string]bool{}
		for i := range typ.NumField() {
			name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			fields[name] = true
			if _, ok := schemaProps[name]; !ok {
				t.Errorf("%s field %q is missing from the outputSchema", where, name)
			}
		}
		for name := range schemaProps {
			if !fields[name] {
				t.Errorf("outputSchema names %s.%s, which the report does not have", where, name)
			}
		}
	}
	check("report", reflect.TypeOf(mcpReport{}), top)
	check("results[]", reflect.TypeOf(mcpResult{}), props(top["results"].(map[string]any)["items"].(map[string]any)))
	check("outcomes", reflect.TypeOf(mcpOutcomes{}), props(top["outcomes"].(map[string]any)))
	check("sources[]", reflect.TypeOf(mcpSource{}), props(top["sources"].(map[string]any)["items"].(map[string]any)))
}

// TestMCPInputSchemasMatchArgs is #330's drift guard on the input side:
// each tool's inputSchema properties are exactly the JSON names of its
// argument struct, embedded remediation included. Arguments are decoded
// strictly, so a property the struct lacks would fail every call that uses
// it, and a field the schema lacks would be one no agent can discover.
func TestMCPInputSchemasMatchArgs(t *testing.T) {
	argNames := func(v any) []string {
		var names []string
		for _, f := range reflect.VisibleFields(reflect.TypeOf(v)) {
			if f.Anonymous {
				continue // its fields are listed after it
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			names = append(names, name)
		}
		slices.Sort(names)
		return names
	}
	withSources := mcpConfig{maxQueries: 10, allow: []string{"example.com"}, sources: []string{"ct"}}
	noSources := mcpConfig{maxQueries: 10, allow: []string{"example.com"}}
	for _, tc := range []struct {
		name string
		tool mcp.Tool
		args any
		omit string // a field the schema leaves out in this configuration
	}{
		{"lab_scan", labScanTool(withSources), labScanArgs{}, ""},
		{"scan", scanTool(withSources), scanArgs{}, ""},
		// Without -sources the schema offers no sources argument; a call
		// that passes one gets "sources are off" rather than "unknown field".
		{"scan without -sources", scanTool(noSources), scanArgs{}, "sources"},
		{"explain_stats", explainStatsTool(), explainStatsArgs{}, ""},
		{"diff", diffTool(), diffArgs{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var schema struct {
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
			}
			if err := json.Unmarshal(tc.tool.InputSchema, &schema); err != nil {
				t.Fatalf("inputSchema is not JSON: %v", err)
			}
			var props []string
			for name := range schema.Properties {
				props = append(props, name)
			}
			slices.Sort(props)
			want := slices.DeleteFunc(argNames(tc.args), func(n string) bool { return n == tc.omit })
			if !slices.Equal(props, want) {
				t.Errorf("inputSchema properties %v, argument struct fields %v", props, want)
			}
			for _, name := range schema.Required {
				if _, ok := schema.Properties[name]; !ok {
					t.Errorf("required %q is not a property", name)
				}
			}
		})
	}
}

// TestMCPLabScenariosDescribed covers #275: lab_scan's schema tells the
// agent what each scenario teaches, from the zone files' opening comments.
func TestMCPLabScenariosDescribed(t *testing.T) {
	var schema struct {
		Properties map[string]struct {
			Description string `json:"description"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(labScanTool(mcpConfig{maxQueries: 10}).InputSchema, &schema); err != nil {
		t.Fatalf("lab_scan inputSchema is not JSON: %v", err)
	}
	desc := schema.Properties["scenario"].Description
	for _, name := range labScenarios() {
		about := labScenarioDescription(name)
		if about == "" || strings.Contains(about, "subenum ") || strings.Contains(about, "Run:") || strings.HasPrefix(about, "Lab ") {
			t.Errorf("%s: description %q; want the opening comment without the lab number or the command", name, about)
		}
		if !strings.Contains(desc, name+": "+about) {
			t.Errorf("scenario schema description lacks %s's description:\n%s", name, desc)
		}
	}
	if want := "spot the wildcard. Every name under lab.example resolves... except that a few of them are real hosts with their own addresses."; labScenarioDescription("lab2-wildcard") != want {
		t.Errorf("lab2-wildcard = %q, want %q", labScenarioDescription("lab2-wildcard"), want)
	}
}

// TestE2EMCPStructuredContent: a scan reply carries the report as
// structuredContent too, equal to the JSON in its text (#270).
func TestE2EMCPStructuredContent(t *testing.T) {
	t.Parallel()
	_, replies := runMCPSession(t, nil, mcpCall{"lab_scan", `{"words": ["www", "nope"]}`})
	result := replies[0]["result"].(map[string]any)
	structured, ok := result["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("no structuredContent in %v", result)
	}
	text, _ := toolText(t, replies[0])
	var fromText map[string]any
	if err := json.Unmarshal([]byte(text), &fromText); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(structured, fromText) {
		t.Errorf("structuredContent %v differs from the text report %v", structured, fromText)
	}
}

// TestTypeAndFormatListsAgree is #264's drift guard: completion and the MCP
// schema offer exactly the record types and formats the flags accept.
func TestTypeAndFormatListsAgree(t *testing.T) {
	for _, typ := range dns.Types() {
		if !slices.Contains(valueChoices["type"], typ) {
			t.Errorf("-type completion lacks %s", typ)
		}
	}
	for _, f := range output.Formats() {
		if _, err := output.ParseFormat(f); err != nil {
			t.Errorf("output.Formats lists %q, which ParseFormat rejects: %v", f, err)
		}
	}
	if !slices.Equal(valueChoices["format"], output.Formats()) {
		t.Errorf("-format completion %v, want %v", valueChoices["format"], output.Formats())
	}
	var schema struct {
		Items struct {
			Enum []string `json:"enum"`
		} `json:"items"`
	}
	raw, err := json.Marshal(recordTypeSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(schema.Items.Enum, dns.Types()) {
		t.Errorf("MCP types enum %v, want %v", schema.Items.Enum, dns.Types())
	}
}

// TestMCPInputSchemaQuoting checks that the tools' input schemas are encoded,
// not spliced together: a value holding a quote, backslash or newline stays
// inside its string, and the properties keep the order they were written in.
func TestMCPInputSchemaQuoting(t *testing.T) {
	hostile := `a.example", "injected": {"x": "\` + "\n"
	cfg := mcpConfig{maxQueries: 10, allow: []string{hostile}, sources: []string{hostile}}
	raw := scanTool(cfg).InputSchema
	var schema struct {
		Type       string `json:"type"`
		Properties map[string]struct {
			Description string `json:"description"`
			Items       struct {
				Enum []string `json:"enum"`
			} `json:"items"`
		} `json:"properties"`
		Required             []string `json:"required"`
		AdditionalProperties *bool    `json:"additionalProperties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("scan inputSchema is not JSON: %v\n%s", err, raw)
	}
	if _, ok := schema.Properties["injected"]; ok {
		t.Error("a quoted value added a property to the schema")
	}
	if want := "Domain to enumerate: one of " + hostile + ", or a subdomain of one."; schema.Properties["domain"].Description != want {
		t.Errorf("domain description = %q, want %q", schema.Properties["domain"].Description, want)
	}
	if got := schema.Properties["sources"].Items.Enum; !slices.Equal(got, []string{hostile}) {
		t.Errorf("sources enum = %q, want the value unchanged", got)
	}
	if schema.Type != "object" || !slices.Equal(schema.Required, []string{"domain"}) ||
		schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Errorf("scan schema envelope = %s", raw)
	}
	order := []string{`"domain"`, `"words"`, `"types"`, `"max_queries"`, `"sources"`, `"retry_inconclusive"`, `"auto_rate"`, `"exclude"`, `"depth"`}
	at := 0
	for _, name := range order {
		i := strings.Index(string(raw[at:]), name+":")
		if i < 0 {
			t.Fatalf("property %s missing or out of order in %s", name, raw)
		}
		at += i
	}
}

// TestE2EMCPSessionBudget covers #240: -max-calls caps a session's scan
// calls, so a looping agent cannot multiply -max-queries without end.
func TestE2EMCPSessionBudget(t *testing.T) {
	t.Parallel()
	zone, err := labzone.Load(filepath.Join("examples", "labs", "lab1-first-scan.zone"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := dnsserver.Listen(dnsserver.Options{}, zone.Handler([]string{"lab.example"}))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	call := mcpCall{"scan", `{"domain": "lab.example", "words": ["www"]}`}
	_, replies := runMCPSession(t, []string{"-allow", "lab.example", "-dns-server", srv.Addr, "-rate", "1000", "-timeout", "5000", "-max-calls", "2"},
		call, call, call)
	// Calls run one at a time but in no fixed order: exactly one of the
	// three finds the budget spent.
	refused := 0
	for i, r := range replies {
		text, isErr := toolText(t, r)
		switch {
		case isErr && strings.Contains(text, "allows 2 scan calls per session"):
			refused++
		case isErr:
			t.Errorf("call %d failed: %s", i, text)
		}
	}
	if refused != 1 {
		t.Errorf("%d calls refused by the session budget, want 1", refused)
	}
}

// TestMCPInvalidCallsSpendNoBudget covers #378: a scan call that cannot
// start sends no query, so it does not use up the session's -max-calls.
func TestMCPInvalidCallsSpendNoBudget(t *testing.T) {
	t.Parallel()
	zone, err := labzone.Load(filepath.Join("examples", "labs", "lab1-first-scan.zone"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := dnsserver.Listen(dnsserver.Options{}, zone.Handler([]string{"lab.example"}))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	tool := scanTool(mcpConfig{allow: []string{"lab.example"}, dnsServer: srv.Addr, maxQueries: 10, rate: 1000,
		maxDuration: time.Minute, timeout: 5 * time.Second, maxCalls: 1})
	for _, bad := range []string{
		`{"domain": "lab.example", "words": ["www"], "types": ["SRV"]}`,
		`{"domain": "lab.example", "words": []}`,
		`{"domain": "lab.example", "words": ["www"], "exclude": ["*."]}`,
	} {
		r := tool.Call(t.Context(), json.RawMessage(bad))
		if !r.IsError || !strings.Contains(r.Text, verdictNotRun) {
			t.Errorf("%s: want a not_run error, got %+v", bad, r)
		}
	}
	r := tool.Call(t.Context(), json.RawMessage(`{"domain": "lab.example", "words": ["www"]}`))
	if r.IsError {
		t.Errorf("valid call after invalid ones: %s", r.Text)
	}
	if r := tool.Call(t.Context(), json.RawMessage(`{"domain": "lab.example", "words": ["www"]}`)); !strings.Contains(r.Text, "allows 1 scan calls per session") {
		t.Errorf("second valid call: want the budget spent, got %s", r.Text)
	}
}

func TestMCPFlagErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"-max-queries", "0"}, exitUsage, "-max-queries must be at least 1"},
		{[]string{"-rate", "0"}, exitUsage, "-rate must be at least 1"},
		{[]string{"-max-duration", "0s"}, exitUsage, "-max-duration must be positive"},
		{[]string{"-timeout", "0"}, exitUsage, "-timeout must be at least 1"},
		{[]string{"-allow", "not a domain"}, exitUsage, `-allow "not a domain"`},
		{[]string{"-dns-server", "nope"}, exitUsage, "-dns-server"},
		{[]string{"-sources", "ct,dns"}, exitUsage, `unknown source "dns"`},
		{[]string{"-max-calls", "0"}, exitUsage, "-max-calls must be at least 1"},
		{[]string{"example.com"}, exitUsage, "unexpected argument"},
		{[]string{"-h"}, exitOK, "Model Context Protocol"},
	} {
		var stdout, stderr bytes.Buffer
		code := runWith(runArgs{args: append([]string{"mcp"}, tc.args...), stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr})
		if code != tc.code || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("mcp %v: exit %d, stderr %q; want %d containing %q", tc.args, code, stderr.String(), tc.code, tc.want)
		}
		if stdout.Len() != 0 {
			t.Errorf("mcp %v wrote to stdout, which carries the protocol: %q", tc.args, stdout.String())
		}
	}
}

func TestMCPAllowed(t *testing.T) {
	allow := []string{"example.com"}
	for domain, want := range map[string]bool{
		"example.com": true, "www.example.com": true, "a.b.example.com": true,
		"notexample.com": false, "example.com.evil.test": false, "com": false,
	} {
		if got := allowed(allow, domain); got != want {
			t.Errorf("allowed(%q) = %v, want %v", domain, got, want)
		}
	}
	if allowed(nil, "example.com") {
		t.Error("an empty allow-list allowed a domain")
	}
}

// TestE2EMCPDiff covers #333: diff compares a results file with a scan
// report, reports a re-pointed alias or a new address as changed but not
// address rotation behind a CNAME, and calls absent names missing.
func TestE2EMCPDiff(t *testing.T) {
	t.Parallel()
	quote := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	previous := quote(`[
  {"subdomain": "www.example.com", "records": [{"type": "A", "value": "192.0.2.1"}]},
  {"subdomain": "cdn.example.com", "records": [{"type": "CNAME", "value": "x.cdn.example."}, {"type": "A", "value": "192.0.2.5"}]},
  {"subdomain": "alias.example.com", "records": [{"type": "CNAME", "value": "a.example."}]},
  {"subdomain": "old.example.com", "records": [{"type": "A", "value": "192.0.2.9"}]}
]`)
	current := quote(`{"domain": "example.com", "verdict": "complete", "results": [
  {"name": "www.example.com", "records": ["A 192.0.2.2"]},
  {"name": "cdn.example.com", "records": ["CNAME x.cdn.example.", "A 192.0.2.99"]},
  {"name": "alias.example.com", "records": ["CNAME b.example."]},
  {"name": "new.example.com", "records": ["AAAA 2001:db8::1"]}
]}`)
	_, labReplies := runMCPSession(t, nil, mcpCall{"lab_scan", `{"words": ["www", "mail"]}`})
	labReport, _ := toolText(t, labReplies[0])

	_, replies := runMCPSession(t, nil,
		mcpCall{"diff", `{"previous": ` + previous + `, "current": ` + current + `}`},
		mcpCall{"diff", `{"previous": ` + previous + `, "current": ` + current + `, "types": ["CNAME"]}`},
		mcpCall{"diff", `{"previous": "www.lab.example\nold.lab.example\n", "current": ` + quote(labReport) + `}`},
		mcpCall{"diff", `{"previous": "", "current": "", "types": ["SOA"]}`},
		mcpCall{"diff", `{"previous": "", "current": "{\"results\": 3}"}`},
	)
	diffOf := func(i int) mcpDiffReport {
		t.Helper()
		text, isErr := toolText(t, replies[i])
		var r mcpDiffReport
		if err := json.Unmarshal([]byte(text), &r); isErr || err != nil {
			t.Fatalf("call %d: not a diff report (isError %v): %s", i, isErr, text)
		}
		structured := replies[i]["result"].(map[string]any)["structuredContent"]
		var fromText any
		_ = json.Unmarshal([]byte(text), &fromText)
		if !reflect.DeepEqual(structured, fromText) {
			t.Errorf("call %d: structuredContent %v differs from the text %v", i, structured, fromText)
		}
		return r
	}
	names := func(ns []mcpDiffName) []string {
		out := []string{}
		for _, n := range ns {
			out = append(out, n.Name)
		}
		return out
	}

	r := diffOf(0)
	if got := names(r.Added); !slices.Equal(got, []string{"new.example.com"}) {
		t.Errorf("added = %v", got)
	}
	if got := names(r.Missing); !slices.Equal(got, []string{"old.example.com"}) || !slices.Equal(r.Missing[0].Records, []string{"A 192.0.2.9"}) {
		t.Errorf("missing = %+v", r.Missing)
	}
	// cdn's address rotated behind an unchanged CNAME: not a change.
	if got := names(r.Changed); !slices.Equal(got, []string{"alias.example.com", "www.example.com"}) || !r.RecordsCompared {
		t.Errorf("changed = %v (records_compared %v), want alias and www", got, r.RecordsCompared)
	}
	if c := r.Changed[0]; !slices.Equal(c.Records, []string{"CNAME b.example."}) || !slices.Equal(c.PreviousRecords, []string{"CNAME a.example."}) {
		t.Errorf("alias change = %+v", c)
	}
	if len(r.Notes) == 0 || !strings.Contains(r.Notes[0], "unverified") {
		t.Errorf("notes %q do not say missing names are unverified", r.Notes)
	}

	if got := names(diffOf(1).Changed); !slices.Equal(got, []string{"alias.example.com"}) {
		t.Errorf("changed over CNAME only = %v, want alias", got)
	}

	r = diffOf(2)
	if !slices.Equal(names(r.Missing), []string{"old.lab.example"}) || !slices.Equal(names(r.Added), []string{"mail.lab.example"}) || r.RecordsCompared {
		t.Errorf("text vs lab_scan report: %+v, want mail added, old missing, no record comparison", r)
	}

	for i, want := range map[int]string{3: "types:", 4: "current: reading the report's results"} {
		if text, isErr := toolText(t, replies[i]); !isErr || !strings.Contains(text, want) {
			t.Errorf("call %d: %q (isError %v), want an error containing %q", i, text, isErr, want)
		}
	}
}

// TestMCPDiffSchemaCoversTheReport keeps diff's outputSchema and
// mcpDiffReport in step, as TestMCPReportSchemaCoversTheReport does for scan.
func TestMCPDiffSchemaCoversTheReport(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(mcpDiffSchema, &schema); err != nil {
		t.Fatalf("outputSchema is not JSON: %v", err)
	}
	props := func(s map[string]any) map[string]any { return s["properties"].(map[string]any) }
	check := func(where string, typ reflect.Type, schemaProps map[string]any) {
		t.Helper()
		var fields, keys []string
		for i := range typ.NumField() {
			name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			fields = append(fields, name)
		}
		for k := range schemaProps {
			keys = append(keys, k)
		}
		slices.Sort(fields)
		slices.Sort(keys)
		if !slices.Equal(fields, keys) {
			t.Errorf("%s: fields %v, schema properties %v", where, fields, keys)
		}
	}
	top := props(schema)
	check("report", reflect.TypeOf(mcpDiffReport{}), top)
	for _, list := range []string{"added", "missing", "changed"} {
		check(list+"[]", reflect.TypeOf(mcpDiffName{}), props(top[list].(map[string]any)["items"].(map[string]any)))
	}
}

// TestE2EMCPExplainStats feeds explain_stats a real -stats file and jsonl
// output from a simulated scan.
func TestE2EMCPExplainStats(t *testing.T) {
	t.Parallel()
	statsFile := filepath.Join(t.TempDir(), "stats.json")
	var jsonl, stderr bytes.Buffer
	args := []string{"-simulate", "-hit-rate", "50", "-seed", "1", "-max-queries", "5", "-w", "examples/labs/words.txt", "-stats", statsFile, "-format", "jsonl", "example.com"}
	if code := runWith(runArgs{args: args, stdin: strings.NewReader(""), stdout: &jsonl, stderr: &stderr}); code != exitOK {
		t.Fatalf("simulated scan exited %d: %s", code, stderr.String())
	}
	stats, err := os.ReadFile(statsFile)
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	_, replies := runMCPSession(t, nil,
		mcpCall{"explain_stats", `{"stats": ` + quote(string(stats)) + `}`},
		mcpCall{"explain_stats", `{"stats": ` + quote(jsonl.String()) + `}`},
		mcpCall{"explain_stats", `{"stats": "{\"found\": 3}"}`},
	)
	for i := range 2 {
		text, isErr := toolText(t, replies[i])
		for _, want := range []string{"Overall verdict: degraded", "simulated run", "example.com: ok", "-max-queries ran out"} {
			if isErr || !strings.Contains(text, want) {
				t.Errorf("call %d: %q lacks %q (isError %v)", i, text, want, isErr)
			}
		}
		// A capped run writes no resume state, so the advice must not offer -resume (#320).
		if text, _ := toolText(t, replies[i]); !strings.Contains(text, "raise it and run the scan again") || strings.Contains(text, "-resume") {
			t.Errorf("call %d: capped-run advice should only say to raise the budget and rerun: %q", i, text)
		}
	}
	if text, isErr := toolText(t, replies[2]); !isErr || !strings.Contains(text, "not a subenum run-quality report") {
		t.Errorf("non-summary input: %q (isError %v)", text, isErr)
	}
}
