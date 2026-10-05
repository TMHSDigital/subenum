// Package dnstest runs internal/dnsserver for hermetic tests (#67): servers
// stop on test cleanup, and failures to listen fail (or, for IPv6, skip) the
// test.
package dnstest

import (
	"errors"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dnsserver"
)

// The dnsserver types, aliased so tests only import this package.
type (
	// Query is one question the server received.
	Query = dnsserver.Query
	// Reply scripts the answer to a Query.
	Reply = dnsserver.Reply
	// Handler answers one query.
	Handler = dnsserver.Handler
	// Options configure a server.
	Options = dnsserver.Options
	// Server is a running DNS server.
	Server = dnsserver.Server
)

// Common replies.
var (
	NXDomain = dnsserver.NXDomain
	ServFail = dnsserver.ServFail
	Refused  = dnsserver.Refused
	Dropped  = dnsserver.Dropped
)

// Start runs a concurrent IPv4 server answering with h, stopped on cleanup.
func Start(t testing.TB, h Handler) *Server {
	t.Helper()
	return StartWith(t, Options{}, h)
}

// StartWith runs a server with options, stopped on cleanup. With IPv6 set and
// no IPv6 loopback available, the test is skipped.
func StartWith(t testing.TB, opts Options, h Handler) *Server {
	t.Helper()
	s, err := dnsserver.Listen(opts, h)
	if errors.Is(err, dnsserver.ErrNoIPv6) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// StartTLS adds a DNS-over-TLS listener to s answering with h. Use TLSAddr as
// tls://<TLSAddr> and RootCAs to trust it.
func StartTLS(t testing.TB, s *Server, h Handler) {
	t.Helper()
	if err := s.ListenTLS(h); err != nil {
		t.Fatal(err)
	}
}
