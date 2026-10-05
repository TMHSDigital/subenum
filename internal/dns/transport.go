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
	"strings"
	"sync"
	"time"
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

// dialer opens one connection per DNS query, the way Go's resolver expects.
// Go frames queries with a two-byte length prefix on any connection that is
// not a net.PacketConn, which is exactly the DoT wire format; DoH adapts the
// same framing to HTTP requests.
type dialer interface {
	dial(ctx context.Context, network string) (net.Conn, error)
}

// newDialer returns the dialer for a -dns-server value. It is validated
// earlier (validate.DNSServer), so errors here fall back to UDP.
func newDialer(timeout time.Duration, server string) dialer {
	switch Transport(server) {
	case TransportTLS:
		host := strings.TrimPrefix(server, "tls://")
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, "853")
		}
		name, _, _ := net.SplitHostPort(host)
		return &dotDialer{
			addr:    host,
			tls:     &tls.Config{ServerName: name, RootCAs: testRootCAs, MinVersion: tls.VersionTLS12},
			timeout: timeout,
			idle:    make(chan idleConn, 16),
		}
	case TransportHTTPS:
		return &dohDialer{
			url: server,
			client: &http.Client{Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{RootCAs: testRootCAs, MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2:   true,
				MaxIdleConnsPerHost: 64,
				IdleConnTimeout:     30 * time.Second,
			}},
		}
	}
	return &udpDialer{addr: server, timeout: timeout}
}

type udpDialer struct {
	addr    string
	timeout time.Duration
}

func (d *udpDialer) dial(ctx context.Context, network string) (net.Conn, error) {
	nd := net.Dialer{Timeout: d.timeout}
	return nd.DialContext(ctx, network, d.addr)
}

// dotIdleMax bounds how long a DoT connection is kept for reuse. Servers
// close idle connections after some seconds; reusing one they already closed
// would fail a query, so connections older than this are discarded.
const dotIdleMax = 5 * time.Second

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
			if time.Since(ic.since) > dotIdleMax {
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
	if resp.StatusCode != http.StatusOK {
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
