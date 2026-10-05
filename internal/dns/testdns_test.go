package dns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/TMHSDigital/subenum/internal/dnstest"
)

// testReply is one table entry for startTestDNS. Names missing from the table
// get NXDOMAIN; a "*" entry answers every missing name. A type the entry has
// no records for gets NODATA (NOERROR with an SOA), as from a real server.
type testReply struct {
	A         string        // IPv4 address for A queries
	AAAA      string        // IPv6 address for AAAA queries
	CNAME     string        // alias target; A queries chase it one hop within the table
	NXDomain  bool          // name does not exist
	Truncated bool          // UDP answers set TC=1 so the client retries over TCP
	ServFailA bool          // A queries get SERVFAIL (other types answer normally)
	ServFail  bool          // every query gets SERVFAIL
	Refused   bool          // every query gets REFUSED
	Drop      bool          // queries are never answered (the client times out)
	DelayA    time.Duration // A answers are sent after this delay
}

// testDNS is a table-driven dnstest server (#67).
type testDNS struct {
	*dnstest.Server
	addr  string
	table map[string]testReply
}

func (s *testDNS) Resolver(d time.Duration) *net.Resolver {
	return NewResolver(d, s.addr)
}

func (s *testDNS) lookup(name string) (testReply, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if r, ok := s.table[name]; ok {
		return r, true
	}
	r, ok := s.table["*"]
	return r, ok
}

func startTestDNS(t *testing.T, table map[string]testReply) *testDNS {
	t.Helper()
	s := &testDNS{table: table}
	s.Server = dnstest.Start(t, s.answer)
	s.addr = s.Addr
	return s
}

func (s *testDNS) answer(q dnstest.Query) dnstest.Reply {
	r, ok := s.lookup(q.Name)
	switch {
	case !ok || r.NXDomain:
		return dnstest.NXDomain
	case r.Drop:
		return dnstest.Dropped
	case r.ServFail:
		return dnstest.ServFail
	case r.Refused:
		return dnstest.Refused
	}
	if r.CNAME != "" {
		// Answer every qtype with the alias; for A also chase one hop so Go's
		// resolver sees a complete CNAME -> A chain.
		reply := dnstest.Reply{CNAME: r.CNAME}
		if target, ok := s.lookup(r.CNAME); ok && q.Type == dnsmessage.TypeA && target.A != "" {
			reply.A = []string{target.A}
		}
		return reply
	}
	reply := dnstest.Reply{Truncate: r.Truncated}
	switch q.Type {
	case dnsmessage.TypeA:
		if r.ServFailA {
			return dnstest.ServFail
		}
		reply.Delay = r.DelayA
		if r.A != "" {
			reply.A = []string{r.A}
		}
	case dnsmessage.TypeAAAA:
		if r.AAAA != "" {
			reply.AAAA = []string{r.AAAA}
		}
	}
	return reply
}

// startBlackHole returns the address of a UDP socket that never answers.
func startBlackHole(t *testing.T) string {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}
