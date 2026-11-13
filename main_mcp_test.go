package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dnsserver"
	"github.com/TMHSDigital/subenum/internal/labzone"
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
