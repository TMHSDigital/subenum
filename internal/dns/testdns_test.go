package dns

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testReply is one table entry for startTestDNS. Missing names NXDOMAIN.
type testReply struct {
	A         string // IPv4 dotted quad; ignored when NXDomain is set
	NXDomain  bool
	Truncated bool // UDP responds TC=1; TCP still returns the full A
}

type testDNS struct {
	addr    string
	udp     net.PacketConn
	tcp     net.Listener
	table   map[string]testReply
	mu      sync.Mutex
	queries atomic.Int64
}

func (s *testDNS) Queries() int64 { return s.queries.Load() }
func (s *testDNS) Resolver(d time.Duration) *net.Resolver {
	return NewResolver(d, s.addr)
}

func (s *testDNS) lookup(name string) testReply {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.table[name]; ok {
		return r
	}
	if r, ok := s.table["*"]; ok {
		return r
	}
	return testReply{NXDomain: true}
}

func startTestDNS(t *testing.T, table map[string]testReply) *testDNS {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		_ = ln.Close()
		t.Fatalf("ListenPacket udp: %v", err)
	}
	s := &testDNS{addr: ln.Addr().String(), udp: pc, tcp: ln, table: table}
	udpDone := make(chan struct{})
	tcpDone := make(chan struct{})

	go func() {
		defer close(udpDone)
		buf := make([]byte, 512)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			s.queries.Add(1)
			resp := s.reply(buf[:n], true)
			if resp != nil {
				_, _ = pc.WriteTo(resp, src)
			}
		}
	}()
	go func() {
		defer close(tcpDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.queries.Add(1)
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				q, err := readTCPDNS(c)
				if err != nil {
					return
				}
				resp := s.reply(q, false)
				if resp != nil {
					_ = writeTCPDNS(c, resp)
				}
			}(conn)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		_ = pc.Close()
		<-udpDone
		<-tcpDone
	})
	return s
}

func startBlackHole(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

func (s *testDNS) reply(query []byte, udp bool) []byte {
	name, qtype, ok := dnsQNameType(query)
	if !ok {
		return nil
	}
	r := s.lookup(name)
	if qtype != 1 { // only A is served; everything else is NXDOMAIN
		return dnsNXDomain(query)
	}
	if r.NXDomain || r.A == "" {
		return dnsNXDomain(query)
	}
	ip := net.ParseIP(r.A).To4()
	if ip == nil {
		return dnsNXDomain(query)
	}
	var addr [4]byte
	copy(addr[:], ip)
	return dnsAResponse(query, addr, udp && r.Truncated)
}

func skipDNSName(msg []byte, off int) (int, bool) {
	for off < len(msg) {
		l := int(msg[off])
		if l == 0 {
			return off + 1, true
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return 0, false
			}
			return off + 2, true
		}
		off += 1 + l
	}
	return 0, false
}

func dnsQNameType(query []byte) (string, uint16, bool) {
	if len(query) < 12 {
		return "", 0, false
	}
	var labels []string
	off := 12
	for off < len(query) {
		l := int(query[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			return "", 0, false
		}
		if off+1+l > len(query) {
			return "", 0, false
		}
		labels = append(labels, string(query[off+1:off+1+l]))
		off += 1 + l
	}
	if off+2 > len(query) {
		return "", 0, false
	}
	qtype := uint16(query[off])<<8 | uint16(query[off+1])
	return strings.ToLower(strings.Join(labels, ".")), qtype, true
}

func dnsAResponse(query []byte, ip [4]byte, truncated bool) []byte {
	if len(query) < 12 {
		return nil
	}
	qend, ok := skipDNSName(query, 12)
	if !ok || qend+4 > len(query) {
		return nil
	}
	qend += 4
	flags := uint16(0x8400)
	if truncated {
		flags |= 0x0200
	}
	if query[2]&0x01 != 0 {
		flags |= 0x0100
	}
	resp := make([]byte, 0, 64)
	resp = append(resp, query[0], query[1])
	resp = append(resp, byte(flags>>8), byte(flags))
	resp = append(resp, 0, 1) // QDCOUNT
	if truncated {
		resp = append(resp, 0, 0)
	} else {
		resp = append(resp, 0, 1)
	}
	resp = append(resp, 0, 0, 0, 0)
	resp = append(resp, query[12:qend]...)
	if !truncated {
		resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ip[0], ip[1], ip[2], ip[3])
	}
	return resp
}

func dnsNXDomain(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := append([]byte(nil), query...)
	resp[2] |= 0x80
	resp[3] = (resp[3] & 0xF0) | 0x03
	return resp
}

func writeTCPDNS(conn net.Conn, msg []byte) error {
	var hdr [2]byte
	hdr[0] = byte(len(msg) >> 8)
	hdr[1] = byte(len(msg))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(msg)
	return err
}

func readTCPDNS(conn net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
