package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"github.com/TMHSDigital/subenum/internal/labzone"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/report"
	"github.com/TMHSDigital/subenum/internal/scan"
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
	if want := []string{"lab_scan", "explain_stats"}; !slices.Equal(tools, want) {
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
	if want := []string{"lab_scan", "scan", "explain_stats"}; !slices.Equal(tools, want) {
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

// fakeSource is a passive source for tests: it returns names, or err.
type fakeSource struct {
	names []string
	err   error
}

func (f fakeSource) Names(context.Context, string) ([]string, error) { return f.names, f.err }

// TestE2EMCPScanSources checks that scan seeds candidates from the passive
// sources the operator enabled and only those, reporting each one (#268).
func TestE2EMCPScanSources(t *testing.T) {
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

// TestE2EMCPArgumentErrors covers the tool-argument checks the allow-list
// test does not (#258): each bad call is an isError result, and the server
// keeps answering after a scan that could not start.
func TestE2EMCPArgumentErrors(t *testing.T) {
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
		"Error: resolver stopped answering", "Next time: lower -rate", "because -max-duration ran out",
		"(a wildcard)", "2 results have a subdomain-takeover hint", "1 public names answer with internal",
		"Zone transfer (AXFR) was allowed by ns1.lab.example", "plain NSEC", "Passive source wayback failed (503)",
		"Permutation pass: 40 candidates from 4 seeds, 1 found", "Compared with prev.jsonl: 1 added, 2 removed",
		"3 earlier names could not be checked",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("explanation lacks %q:\n%s", want, text)
		}
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
		{name: "error before testing", errMsg: "wildcard zone", want: verdictNotRun},
		{name: "error after a complete scan", c: counts{nx: 10}, errMsg: "boom", want: "unreliable"},
	} {
		c := tc.c
		pub := subenum.Stats{Found: c.found, NXDomain: c.nx, Timeout: c.timeout, Skipped: c.skipped, Expired: c.expired, Aborted: c.aborted, Wildcard: c.wildcard}
		eng := scan.Stats{Found: c.found, NXDomain: c.nx, Timeout: c.timeout, Skipped: c.skipped, Expired: c.expired, Aborted: c.aborted, Wildcard: c.wildcard}
		status := "ok"
		if tc.interrupted {
			status = "interrupted"
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
	if err := json.Unmarshal(recordTypeSchema, &schema); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(schema.Items.Enum, dns.Types()) {
		t.Errorf("MCP types enum %v, want %v", schema.Items.Enum, dns.Types())
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

// TestE2EMCPExplainStats feeds explain_stats a real -stats file and jsonl
// output from a simulated scan.
func TestE2EMCPExplainStats(t *testing.T) {
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
	}
	if text, isErr := toolText(t, replies[2]); !isErr || !strings.Contains(text, "not a subenum run-quality report") {
		t.Errorf("non-summary input: %q (isError %v)", text, isErr)
	}
}
