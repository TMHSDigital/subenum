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
	"errors"
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
	// OutputSchema, when set, describes Result.Structured, which every
	// successful call of the tool then returns (#270).
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  Annotations     `json:"annotations"`

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
// reports a failure the model should see as one. Structured, when set, is
// sent as structuredContent for clients that read results as data; Text
// should then hold the same value as JSON, for clients that do not.
type Result struct {
	Text       string
	IsError    bool
	Structured any
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
	// stop ends the session. A failed write calls it: the client is gone,
	// so calls still queued would scan for nobody (#240).
	stop context.CancelFunc

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
	ss := &session{srv: s, w: w, stop: cancel, calls: make(chan struct{}, 1), cancels: map[string]context.CancelFunc{}}
	// When input ends, finish what was asked, for clients that send their
	// requests and close stdin; ctx, or a client that stopped reading, stops
	// it sooner.
	defer ss.wg.Wait()

	lines := make(chan inputLine)
	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReaderSize(r, 64<<10)
		for {
			line, err := readMessageLine(br)
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				errc <- err
				close(lines)
				return
			}
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line, ok := <-lines:
			if !ok {
				return <-errc
			}
			if line.tooLong {
				// Answer it and read on, rather than drop the session (#241).
				ss.reply(nil, nil, &rpcError{codeParse, fmt.Sprintf("message too large: more than %d bytes", maxMessage)})
				continue
			}
			ss.dispatch(ctx, line.data)
		}
	}
}

// inputLine is one line of input, or the note that it was too long.
type inputLine struct {
	data    []byte
	tooLong bool
}

// readMessageLine reads one newline-terminated line. A line longer than
// maxMessage is read to its end and dropped, so the next one still parses.
// The last line may lack its newline; io.EOF comes after it.
func readMessageLine(br *bufio.Reader) (inputLine, error) {
	var line inputLine
	for {
		chunk, err := br.ReadSlice('\n')
		if !line.tooLong {
			if len(line.data)+len(chunk) > maxMessage+1 { // +1: the newline
				line.data, line.tooLong = nil, true
			} else {
				line.data = append(line.data, chunk...)
			}
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err == nil:
			return line, nil
		case errors.Is(err, io.EOF) && (len(line.data) > 0 || line.tooLong):
			return line, nil // a last line without a newline
		default:
			return inputLine{}, err
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
	key := string(req.ID)
	ss.mu.Lock()
	if _, busy := ss.cancels[key]; busy {
		ss.mu.Unlock()
		// Reusing the ID of a request still running would make that one
		// impossible to cancel (#241).
		ss.reply(req.ID, nil, &rpcError{codeInvalidRequest, "a request with this id is still in progress"})
		return
	}
	ctx, cancel := context.WithCancel(ctx)
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
		Meta      struct {
			ProgressToken json.RawMessage `json:"progressToken"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{codeInvalidParams, "invalid tools/call params: " + err.Error()}
	}
	if tok := p.Meta.ProgressToken; len(tok) > 0 && string(tok) != "null" {
		ctx = context.WithValue(ctx, progressKey{}, &progressReporter{ss: ss, token: tok})
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
	m := map[string]any{
		"content": []map[string]any{{"type": "text", "text": r.Text}},
		"isError": r.IsError,
	}
	if r.Structured != nil {
		m["structuredContent"] = r.Structured
	}
	return m
}

func (ss *session) reply(id json.RawMessage, result any, rerr *rpcError) {
	if id == nil {
		id = json.RawMessage("null")
	}
	b, err := json.Marshal(response{JSONRPC: "2.0", ID: id, Result: result, Error: rerr})
	if err != nil {
		b, _ = json.Marshal(response{JSONRPC: "2.0", ID: id, Error: &rpcError{-32603, "internal error: " + err.Error()}})
	}
	ss.write(b)
}

// write sends one message line. A failed write means the client stopped
// reading, so the session ends: the running call is cancelled, and queued
// ones never start.
func (ss *session) write(b []byte) {
	ss.writeMu.Lock()
	defer ss.writeMu.Unlock()
	if _, err := ss.w.Write(append(b, '\n')); err != nil && ss.stop != nil {
		ss.stop()
	}
}

// progressKey carries a tool call's progress reporter in its context.
type progressKey struct{}

// progressReporter sends notifications/progress for one tool call whose
// request carried _meta.progressToken (#267).
type progressReporter struct {
	ss    *session
	token json.RawMessage

	mu   sync.Mutex
	sent bool
	last float64
}

// ReportProgress tells the client how far the tool call ctx belongs to has
// got, if the client asked for progress; otherwise it does nothing. total is
// left out when zero, and message when empty. A report whose progress is not
// above the last one sent is dropped, as the protocol requires progress to
// increase.
func ReportProgress(ctx context.Context, progress, total float64, message string) {
	p, _ := ctx.Value(progressKey{}).(*progressReporter)
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sent && progress <= p.last {
		return
	}
	params := map[string]any{"progressToken": p.token, "progress": progress}
	if total > 0 {
		params["total"] = total
	}
	if message != "" {
		params["message"] = message
	}
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": params})
	if err != nil {
		return
	}
	p.sent, p.last = true, progress
	p.ss.write(b)
}
