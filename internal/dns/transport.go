package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/TMHSDigital/subenum/internal/validate"
)

// Transports a -dns-server can use (#86).
const (
	TransportUDP   = "udp"   // ip:port; UDP with TCP fallback on truncation
	TransportTLS   = "tls"   // tls://host[:853]; DNS over TLS (RFC 7858)
	TransportHTTPS = "https" // https://host/path; DNS over HTTPS (RFC 8484)
)

// Transport names the transport a -dns-server value selects.
func Transport(server string) string {
	switch {
	case strings.HasPrefix(server, "tls://"):
		return TransportTLS
	case strings.HasPrefix(server, "https://"):
		return TransportHTTPS
	}
	return TransportUDP
}

// testRootCAs, when set by tests, replaces the system roots for DoT and DoH.
var testRootCAs *x509.CertPool

// dialer opens a connection per DNS query, the way Go's resolver expects
// (UDP and DoT dialers hand out pooled ones).
// Go frames queries with a two-byte length prefix on any connection that is
// not a net.PacketConn, which is exactly the DoT wire format; DoH adapts the
// same framing to HTTP requests.
type dialer interface {
	dial(ctx context.Context, network string) (net.Conn, error)
}

// idleCloser is a dialer that keeps connections between queries.
type idleCloser interface {
	closeIdle()
}

// pooledDialers maps a resolver from NewResolver to its dialer,
// so CloseIdleConnections can find it. Keys are weak, and an entry is
// removed (and its connections closed) once the resolver is collected.
var pooledDialers sync.Map // weak.Pointer[net.Resolver] -> idleCloser

func registerDialer(r *net.Resolver, d dialer) {
	c, ok := d.(idleCloser)
	if !ok {
		return
	}
	key := weak.Make(r)
	pooledDialers.Store(key, c)
	runtime.AddCleanup(r, func(k weak.Pointer[net.Resolver]) {
		if v, ok := pooledDialers.LoadAndDelete(k); ok {
			v.(idleCloser).closeIdle()
		}
	}, key)
}

// CloseIdleConnections closes the UDP sockets, DoT connections and idle DoH
// connections a resolver from NewResolver keeps for reuse. The resolver stays usable. A
// scan calls it when it ends, so a long-lived program that scans repeatedly
// does not hold connections open between scans.
func CloseIdleConnections(r *net.Resolver) {
	if r == nil {
		return
	}
	if v, ok := pooledDialers.Load(weak.Make(r)); ok {
		v.(idleCloser).closeIdle()
	}
}

// dotIdleConns bounds the DoT connections kept for reuse; it matches the
// default -t, so a default scan rarely closes one only to dial it again.
const dotIdleConns = 128

// newDialer returns the dialer for a -dns-server value. It is validated
// earlier (validate.DNSServer), so errors here fall back to UDP. A UDP
// dialer keeps its idle sockets within budget, which a pool shares across
// its members; nil gives it a budget of its own.
func newDialer(timeout time.Duration, server string, budget *idleBudget) dialer {
	switch Transport(server) {
	case TransportTLS:
		addr, name, err := validate.DoTAddress(server)
		if err != nil {
			break
		}
		return &dotDialer{
			addr:    addr,
			tls:     &tls.Config{ServerName: name, RootCAs: testRootCAs, MinVersion: tls.VersionTLS12},
			timeout: timeout,
			idle:    make(chan idleConn, dotIdleConns),
		}
	case TransportHTTPS:
		return &dohDialer{
			url: server,
			client: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig:     &tls.Config{RootCAs: testRootCAs, MinVersion: tls.VersionTLS12},
					ForceAttemptHTTP2:   true,
					MaxIdleConnsPerHost: 64,
					IdleConnTimeout:     30 * time.Second,
				},
				// A redirect could send the query somewhere else, or in
				// cleartext over http://; a DoH server has no reason to
				// redirect, so none is followed (#114).
				CheckRedirect: func(req *http.Request, _ []*http.Request) error {
					return fmt.Errorf("DNS-over-HTTPS server redirected to %s; refusing to follow", req.URL.Redacted())
				},
			},
		}
	}
	d := newUDPDialer(server, timeout)
	if budget != nil {
		d.budget = budget
	}
	return d
}

// udpIdleConns bounds the UDP sockets kept for reuse; it covers a busy -t
// without holding thousands of sockets open. A resolver pool shares one
// such budget across its members, so a 10k-resolver -r list keeps at most
// this many idle sockets, not one or more per member (#252).
const udpIdleConns = 512

// idleBudget counts idle UDP sockets against a cap shared by one or more
// dialers.
type idleBudget struct {
	n   atomic.Int64
	max int64
}

func newIdleBudget() *idleBudget { return &idleBudget{max: udpIdleConns} }

// take reserves room for one more idle socket, if there is any.
func (b *idleBudget) take() bool {
	if b.n.Add(1) > b.max {
		b.n.Add(-1)
		return false
	}
	return true
}

// release gives back the room of a socket that left the idle set.
func (b *idleBudget) release() { b.n.Add(-1) }

// udpDialer reuses UDP sockets between queries (#180). Opening and closing
// a socket per query capped live scans near 10k queries per second, nearly
// all of it in socket teardown. Reuse is safe because Go's resolver reads
// until it gets a reply whose ID and question match the query it sent, so a
// late answer to an earlier query on the same socket is skipped. TCP (the
// fallback for truncated answers) still dials per query.
type udpDialer struct {
	addr    string
	timeout time.Duration
	idle    chan *net.UDPConn
	budget  *idleBudget // room for idle sockets, possibly shared
}

func newUDPDialer(addr string, timeout time.Duration) *udpDialer {
	return &udpDialer{addr: addr, timeout: timeout, idle: make(chan *net.UDPConn, udpIdleConns), budget: newIdleBudget()}
}

func (d *udpDialer) dial(ctx context.Context, network string) (net.Conn, error) {
	if network == "udp" {
		select {
		case u := <-d.idle:
			d.budget.release()
			return &pooledUDPConn{UDPConn: u, pool: d}, nil
		default:
		}
	}
	nd := net.Dialer{Timeout: d.timeout}
	c, err := nd.DialContext(ctx, network, d.addr)
	if err != nil {
		return nil, err
	}
	if u, ok := c.(*net.UDPConn); ok {
		return &pooledUDPConn{UDPConn: u, pool: d}, nil
	}
	return c, nil
}

// closeIdle closes every pooled socket.
func (d *udpDialer) closeIdle() {
	for {
		select {
		case u := <-d.idle:
			d.budget.release()
			_ = u.Close()
		default:
			return
		}
	}
}

// pooledUDPConn returns its socket to the pool on Close. It embeds the
// *net.UDPConn so it stays a net.PacketConn: Go's resolver frames messages
// by that. A read or write that failed other than by timing out (such as an
// ICMP port unreachable surfacing as a connection reset) closes the socket
// for good.
type pooledUDPConn struct {
	*net.UDPConn
	pool *udpDialer
	bad  bool
}

func (c *pooledUDPConn) note(err error) {
	var ne net.Error
	if err != nil && (!errors.As(err, &ne) || !ne.Timeout()) {
		c.bad = true
	}
}

func (c *pooledUDPConn) Read(p []byte) (int, error) {
	n, err := c.UDPConn.Read(p)
	c.note(err)
	return n, err
}

func (c *pooledUDPConn) Write(p []byte) (int, error) {
	n, err := c.UDPConn.Write(p)
	c.note(err)
	return n, err
}

func (c *pooledUDPConn) Close() error {
	if c.bad || c.SetDeadline(time.Time{}) != nil || !c.pool.budget.take() {
		return c.UDPConn.Close()
	}
	select {
	case c.pool.idle <- c.UDPConn:
		return nil
	default:
		c.pool.budget.release()
		return c.UDPConn.Close()
	}
}

// dotIdleMax bounds how long a DoT connection is kept for reuse. Servers
// close idle connections after some seconds; reusing one they already closed
// would fail a query, so connections older than this are discarded. A
// younger one is still probed before reuse (see alive).
const dotIdleMax = 4 * time.Second

// dotProbe is how long alive waits for a pooled connection to show it was
// closed. A closed one reports EOF at once; a live one has nothing to read.
const dotProbe = time.Millisecond

type idleConn struct {
	conn  *tls.Conn
	since time.Time
}

// dotDialer keeps a small pool of TLS connections so most queries skip the
// handshake.
type dotDialer struct {
	addr    string
	tls     *tls.Config
	timeout time.Duration
	idle    chan idleConn
}

func (d *dotDialer) dial(ctx context.Context, _ string) (net.Conn, error) {
	for {
		select {
		case ic := <-d.idle:
			// A connection the server already closed would fail this query
			// after it had been counted and paced, so it is checked first
			// (#113).
			if time.Since(ic.since) > dotIdleMax || !alive(ic.conn) {
				_ = ic.conn.Close()
				continue
			}
			return &pooledConn{Conn: ic.conn, pool: d}, nil
		default:
		}
		break
	}
	td := tls.Dialer{NetDialer: &net.Dialer{Timeout: d.timeout}, Config: d.tls}
	c, err := td.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	return &pooledConn{Conn: c.(*tls.Conn), pool: d}, nil
}

// alive reports whether an idle DoT connection is still open. Between
// queries a server sends nothing, so a read that times out means open, and
// EOF, an error or unexpected data means it must not be reused. A read
// timeout leaves a tls.Conn usable.
func alive(c *tls.Conn) bool {
	if err := c.SetReadDeadline(time.Now().Add(dotProbe)); err != nil {
		return false
	}
	var b [1]byte
	_, err := c.Read(b[:])
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		return false
	}
	return c.SetReadDeadline(time.Time{}) == nil
}

// closeIdle closes every pooled connection.
func (d *dotDialer) closeIdle() {
	for {
		select {
		case ic := <-d.idle:
			_ = ic.conn.Close()
		default:
			return
		}
	}
}

// pooledConn returns its TLS connection to the pool on Close, unless a read
// or write failed (the stream may then hold a partial message).
type pooledConn struct {
	*tls.Conn
	pool *dotDialer
	bad  bool
}

func (c *pooledConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.bad = true
	}
	return n, err
}

func (c *pooledConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		c.bad = true
	}
	return n, err
}

func (c *pooledConn) Close() error {
	if c.bad {
		return c.Conn.Close()
	}
	_ = c.SetDeadline(time.Time{})
	select {
	case c.pool.idle <- idleConn{conn: c.Conn, since: time.Now()}:
		return nil
	default:
		return c.Conn.Close()
	}
}

// dohDialer turns each query into an HTTPS POST (RFC 8484). The HTTP client
// keeps connections alive (HTTP/2 where the server offers it), so "dialing"
// is cheap.
type dohDialer struct {
	url    string
	client *http.Client
}

func (d *dohDialer) dial(ctx context.Context, _ string) (net.Conn, error) {
	return &dohConn{ctx: ctx, d: d}, nil
}

func (d *dohDialer) closeIdle() { d.client.CloseIdleConnections() }

// dohConn accepts length-prefixed DNS messages on Write, exchanges each one
// over HTTPS, and serves the length-prefixed answers on Read.
type dohConn struct {
	ctx      context.Context
	d        *dohDialer
	mu       sync.Mutex
	in, out  bytes.Buffer
	deadline time.Time
}

func (c *dohConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.in.Write(p)
	for c.in.Len() >= 2 {
		size := int(binary.BigEndian.Uint16(c.in.Bytes()[:2]))
		if c.in.Len() < 2+size {
			break
		}
		msg := append([]byte(nil), c.in.Next(2 + size)[2:]...)
		answer, err := c.exchange(msg)
		if err != nil {
			return 0, err
		}
		c.out.Write(binary.BigEndian.AppendUint16(nil, uint16(len(answer)))) //nolint:gosec // DNS messages are under 64 KiB
		c.out.Write(answer)
	}
	return len(p), nil
}

func (c *dohConn) exchange(msg []byte) ([]byte, error) {
	ctx := c.ctx
	if !c.deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, c.deadline)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.d.url, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := c.d.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) && ue.Timeout() {
			return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		// The HTTP form of REFUSED: the server is shedding load. Worded so
		// Classify counts it as refused, the rate-limit signal (#114).
		return nil, fmt.Errorf("DNS-over-HTTPS server refused the query (HTTP %s)", resp.Status)
	default:
		return nil, fmt.Errorf("DNS-over-HTTPS server returned %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

func (c *dohConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.out.Len() == 0 {
		return 0, io.EOF
	}
	return c.out.Read(p)
}

func (c *dohConn) Close() error                       { return nil }
func (c *dohConn) LocalAddr() net.Addr                { return dohAddr{} }
func (c *dohConn) RemoteAddr() net.Addr               { return dohAddr{} }
func (c *dohConn) SetReadDeadline(time.Time) error    { return nil }
func (c *dohConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }
func (c *dohConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

type dohAddr struct{}

func (dohAddr) Network() string { return "https" }
func (dohAddr) String() string  { return "doh" }
