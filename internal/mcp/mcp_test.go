package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// serve runs s over in-memory pipes and returns a function sending one line
// and one reading the next response.
func serve(t *testing.T, s *Server) (send func(string), recv func() map[string]any, closeInput func()) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- s.Serve(context.Background(), inR, outW)
		_ = outW.Close()
	}()
	t.Cleanup(func() {
		_ = inW.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after its input closed")
		}
	})
	sc := bufio.NewScanner(outR)
	send = func(line string) {
		if _, err := io.WriteString(inW, line+"\n"); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	recv = func() map[string]any {
		t.Helper()
		got := make(chan map[string]any, 1)
		go func() {
			if !sc.Scan() {
				got <- nil
				return
			}
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				t.Errorf("response is not JSON: %q", sc.Text())
			}
			got <- m
		}()
		select {
		case m := <-got:
			if m == nil {
				t.Fatal("no response")
			}
			return m
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for a response")
		}
		return nil
	}
	return send, recv, func() { _ = inW.Close() }
}

func echoTool() Tool {
	return Tool{
		Name:        "echo",
		Description: "returns its argument",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Call: func(_ context.Context, args json.RawMessage) Result {
			return Result{Text: string(args)}
		},
	}
}

func TestInitializeNegotiatesTheVersion(t *testing.T) {
	send, recv, _ := serve(t, &Server{Name: "subenum", Version: "1.2.3", Instructions: "be careful"})
	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	r := recv()["result"].(map[string]any)
	if r["protocolVersion"] != "2025-03-26" {
		t.Errorf("protocolVersion = %v, want the client's supported 2025-03-26", r["protocolVersion"])
	}
	if r["instructions"] != "be careful" || r["serverInfo"].(map[string]any)["version"] != "1.2.3" {
		t.Errorf("result = %v", r)
	}
	if _, ok := r["capabilities"].(map[string]any)["tools"]; !ok {
		t.Errorf("capabilities lack tools: %v", r["capabilities"])
	}
	send(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	if v := recv()["result"].(map[string]any)["protocolVersion"]; v != ProtocolVersion {
		t.Errorf("unknown version answered with %v, want %s", v, ProtocolVersion)
	}
}

func TestRequestsAndErrors(t *testing.T) {
	send, recv, _ := serve(t, &Server{Tools: []Tool{echoTool()}})

	// A notification gets no answer: the ping after it is the next reply.
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":"a","method":"ping"}`)
	if m := recv(); m["id"] != "a" || m["result"] == nil {
		t.Errorf("ping = %v", m)
	}

	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := recv()["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "echo" {
		t.Errorf("tools = %v", tools)
	}

	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}`)
	r := recv()["result"].(map[string]any)
	if text := r["content"].([]any)[0].(map[string]any)["text"]; text != `{"x":1}` || r["isError"] != false {
		t.Errorf("call = %v", r)
	}

	for _, tc := range []struct {
		line string
		code float64
	}{
		{`{not json`, codeParse},
		{`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, codeInvalidRequest},
		{`{"jsonrpc":"1.0","id":4,"method":"ping"}`, codeInvalidRequest},
		{`{"jsonrpc":"2.0","id":5,"method":"resources/list"}`, codeMethodNotFound},
		{`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope"}}`, codeInvalidParams},
	} {
		send(tc.line)
		m := recv()
		e, ok := m["error"].(map[string]any)
		if !ok || e["code"] != tc.code {
			t.Errorf("%s: got %v, want error %v", tc.line, m, tc.code)
		}
	}
}

func TestToolCallsRunOneAtATimeAndCanBeCancelled(t *testing.T) {
	var running, peak atomic.Int32
	started := make(chan struct{}, 2)
	slow := Tool{
		Name:        "slow",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Call: func(ctx context.Context, _ json.RawMessage) Result {
			n := running.Add(1)
			defer running.Add(-1)
			for {
				if p := peak.Load(); n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			started <- struct{}{}
			<-ctx.Done()
			return Result{Text: "stopped: " + ctx.Err().Error()}
		},
	}
	send, recv, _ := serve(t, &Server{Tools: []Tool{slow}})
	send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow"}}`)
	<-started
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"slow"}}`)
	// The second call waits for the first; ping is still answered.
	send(`{"jsonrpc":"2.0","id":3,"method":"ping"}`)
	if m := recv(); m["id"] != float64(3) {
		t.Fatalf("expected the ping reply first, got %v", m)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`)
	if m := recv(); m["id"] != float64(1) {
		t.Fatalf("expected call 1 to end, got %v", m)
	}
	<-started
	send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}`)
	m := recv()
	text := m["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if m["id"] != float64(2) || !strings.HasPrefix(text, "stopped") {
		t.Fatalf("call 2 = %v", m)
	}
	if peak.Load() != 1 {
		t.Errorf("%d calls ran at once, want 1", peak.Load())
	}
}

func TestProgressNotifications(t *testing.T) {
	counter := Tool{
		Name:        "count",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Call: func(ctx context.Context, _ json.RawMessage) Result {
			ReportProgress(ctx, 1, 3, "one")
			ReportProgress(ctx, 1, 3, "again") // not above the last: dropped
			ReportProgress(ctx, 2, 0, "")
			return Result{Text: "done"}
		},
	}
	send, recv, _ := serve(t, &Server{Tools: []Tool{counter}})

	send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"count","_meta":{"progressToken":"tok"}}}`)
	first := recv()
	if first["method"] != "notifications/progress" {
		t.Fatalf("first message = %v, want a progress notification", first)
	}
	p := first["params"].(map[string]any)
	if p["progressToken"] != "tok" || p["progress"] != float64(1) || p["total"] != float64(3) || p["message"] != "one" {
		t.Errorf("first progress params = %v", p)
	}
	second := recv()["params"].(map[string]any)
	if second["progress"] != float64(2) {
		t.Errorf("second progress = %v, want 2 (the repeat of 1 dropped)", second)
	}
	if _, ok := second["total"]; ok {
		t.Errorf("zero total was sent: %v", second)
	}
	if m := recv(); m["id"] != float64(1) {
		t.Fatalf("expected the call result, got %v", m)
	}

	// Without a token the tool's reports go nowhere.
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"count"}}`)
	if m := recv(); m["id"] != float64(2) {
		t.Fatalf("a call without progressToken sent %v before its result", m)
	}
}

func TestInputEndFinishesPendingCalls(t *testing.T) {
	send, recv, closeInput := serve(t, &Server{Tools: []Tool{echoTool()}})
	send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":null}}`)
	closeInput()
	r := recv()["result"].(map[string]any)
	if text := r["content"].([]any)[0].(map[string]any)["text"]; text != "{}" {
		t.Errorf("null arguments reached the tool as %v, want {}", text)
	}
}
