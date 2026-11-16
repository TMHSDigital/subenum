package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// FuzzDispatch: any input line gets at most a JSON reply per request, and
// never panics or hangs the session (#259).
func FuzzDispatch(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`[{"jsonrpc":"2.0","id":3,"method":"ping"}]`,
		`{"id":null}`, `{`, `"x"`, ``,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if strings.ContainsAny(line, "\r\n") {
			return // one line per call
		}
		var out bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = (&Server{Tools: []Tool{echoTool()}}).Serve(ctx, strings.NewReader(line+"\n"), &out)
		if ctx.Err() != nil {
			t.Fatalf("session did not end after input %q", line)
		}
		for _, reply := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			if reply != "" && !json.Valid([]byte(reply)) {
				t.Errorf("input %q: reply %q is not JSON", line, reply)
			}
		}
	})
}
