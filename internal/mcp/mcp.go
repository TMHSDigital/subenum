// Package mcp is a minimal Model Context Protocol server: JSON-RPC 2.0
// messages, one per line, over a reader and a writer (the stdio transport),
// offering tools and nothing else (#131). It is hand-written rather than
// built on an SDK because subenum needs only initialize, ping, tools/list and
// tools/call, and every dependency has to pass govulncheck and keep the go
// directive where it is.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sync"
)

// ProtocolVersion is the newest MCP revision the server speaks. A client
// asking for another supported revision gets that one instead.
const ProtocolVersion = "2025-06-18"

// supportedVersions are the revisions whose tools subset is identical.
var supportedVersions = []string{ProtocolVersion, "2025-03-26", "2024-11-05"}

// maxMessage bounds one incoming line. explain_stats takes a whole -stats
// file as an argument, so it is generous.
const maxMessage = 16 << 20

// JSON-RPC error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// Tool is one tool the server offers.
type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations Annotations     `json:"annotations"`

	// Call runs the tool. ctx is cancelled when the client cancels the
	// request or the session ends.
	Call func(ctx context.Context, args json.RawMessage) Result `json:"-"`
}

// Annotations are hints about a tool's behavior for the client.
type Annotations struct {
	ReadOnlyHint  bool `json:"readOnlyHint"`  // changes nothing on the local machine
	OpenWorldHint bool `json:"openWorldHint"` // talks to systems outside the machine
}

// Result is what a tool call returns: text for the model, and whether it
// reports a failure the model should see as one.
type Result struct {
	Text    string
	IsError bool
}

// Errorf is a failed tool call with a message for the model.
func Errorf(format string, args ...any) Result {
	return Result{Text: fmt.Sprintf(format, args...), IsError: true}
}

// Server answers MCP requests.
type Server struct {
	Name         string
	Version      string
	Instructions string // shown to the model when the session starts
	Tools        []Tool
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// session is one Serve call's state.
type session struct {
	srv *Server

	writeMu sync.Mutex
	w       io.Writer

	// calls runs one tool call at a time, so a client cannot multiply the
	// operator's query budget by calling in parallel.
	calls chan struct{}

	mu      sync.Mutex
	cancels map[string]context.CancelFunc // in-flight requests by ID

	wg sync.WaitGroup
}

// Serve reads requests from r and writes responses to w until r ends or ctx
// is cancelled. Requests are handled concurrently, except tool calls, which
// run one at a time; notifications/cancelled stops the call it names. Serve
// returns once every request it read has been answered, so cancel ctx to
// stop calls still running.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ss := &session{srv: s, w: w, calls: make(chan struct{}, 1), cancels: map[string]context.CancelFunc{}}
	defer ss.wg.Wait() // when input ends, finish what was asked; ctx stops it sooner

	lines := make(chan []byte)
	errc := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), maxMessage)
		for sc.Scan() {
			select {
			case lines <- slices.Clone(sc.Bytes()):
			case <-ctx.Done():
				return
			}
		}
		errc <- sc.Err()
		close(lines)
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line, ok := <-lines:
			if !ok {
				return <-errc
			}
			ss.dispatch(ctx, line)
		}
	}
}

// dispatch handles one line.
func (ss *session) dispatch(ctx context.Context, line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	if line[0] == '[' {
		ss.reply(nil, nil, &rpcError{codeInvalidRequest, "batches are not supported"})
		return
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		ss.reply(nil, nil, &rpcError{codeParse, "parse error: " + err.Error()})
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		if len(req.ID) > 0 {
			ss.reply(req.ID, nil, &rpcError{codeInvalidRequest, `a request needs "jsonrpc": "2.0" and a method`})
		}
		return
	}
	if len(req.ID) == 0 {
		ss.notification(req)
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	key := string(req.ID)
	ss.mu.Lock()
	ss.cancels[key] = cancel
	ss.mu.Unlock()
	ss.wg.Go(func() {
		defer func() {
			ss.mu.Lock()
			delete(ss.cancels, key)
			ss.mu.Unlock()
			cancel()
		}()
		result, rerr := ss.handle(ctx, req)
		ss.reply(req.ID, result, rerr)
	})
}

// notification handles a message that expects no answer.
func (ss *session) notification(req request) {
	if req.Method != "notifications/cancelled" {
		return // notifications/initialized and the rest need nothing
	}
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(req.Params, &p) != nil {
		return
	}
	ss.mu.Lock()
	cancel := ss.cancels[string(p.RequestID)]
	ss.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (ss *session) handle(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := ProtocolVersion
		if slices.Contains(supportedVersions, p.ProtocolVersion) {
			version = p.ProtocolVersion
		}
		result := map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": ss.srv.Name, "version": ss.srv.Version},
		}
		if ss.srv.Instructions != "" {
			result["instructions"] = ss.srv.Instructions
		}
		return result, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		tools := ss.srv.Tools
		if tools == nil {
			tools = []Tool{}
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		return ss.call(ctx, req.Params)
	}
	return nil, &rpcError{codeMethodNotFound, "method not found: " + req.Method}
}

func (ss *session) call(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{codeInvalidParams, "invalid tools/call params: " + err.Error()}
	}
	i := slices.IndexFunc(ss.srv.Tools, func(t Tool) bool { return t.Name == p.Name })
	if i < 0 {
		return nil, &rpcError{codeInvalidParams, "unknown tool: " + p.Name}
	}
	if len(p.Arguments) == 0 || string(p.Arguments) == "null" {
		p.Arguments = json.RawMessage("{}")
	}
	select {
	case ss.calls <- struct{}{}:
	case <-ctx.Done():
		return toolResult(Errorf("cancelled before it started")), nil
	}
	defer func() { <-ss.calls }()
	return toolResult(ss.srv.Tools[i].Call(ctx, p.Arguments)), nil
}

func toolResult(r Result) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": r.Text}},
		"isError": r.IsError,
	}
}

func (ss *session) reply(id json.RawMessage, result any, rerr *rpcError) {
	if id == nil {
		id = json.RawMessage("null")
	}
	b, err := json.Marshal(response{JSONRPC: "2.0", ID: id, Result: result, Error: rerr})
	if err != nil {
		b, _ = json.Marshal(response{JSONRPC: "2.0", ID: id, Error: &rpcError{-32603, "internal error: " + err.Error()}})
	}
	ss.writeMu.Lock()
	defer ss.writeMu.Unlock()
	_, _ = ss.w.Write(append(b, '\n'))
}
