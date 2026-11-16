package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// AXFR and NSEC answers come from servers the scan does not control, so
// their parsers are tested against malformed and hostile input (#257).

// rr is one answer record for msgWith: an owner name and a type, SOA or A.
type rr struct {
	name string
	typ  dnsmessage.Type
}

// msgWith builds a DNS message with the given header and answers, and
// authorities of the given types (NSEC records are opaque to the builder,
// so they are added as unknown resources).
func msgWith(t testing.TB, hdr dnsmessage.Header, answers []rr, authorities ...dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, hdr)
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(b.StartAnswers())
	for _, a := range answers {
		h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(a.name), Class: dnsmessage.ClassINET, TTL: 60}
		switch a.typ {
		case dnsmessage.TypeSOA:
			must(b.SOAResource(h, dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example.test."), MBox: dnsmessage.MustNewName("admin.example.test."), Serial: 1}))
		default:
			must(b.AResource(h, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}))
		}
	}
	must(b.StartAuthorities())
	for _, typ := range authorities {
		h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.test."), Type: typ, Class: dnsmessage.ClassINET, TTL: 60}
		must(b.UnknownResource(h, dnsmessage.UnknownResource{Type: typ, Data: []byte{0}}))
	}
	msg, err := b.Finish()
	must(err)
	return msg
}

func TestReadTransferMessageRejectsBadMessages(t *testing.T) {
	const id = 42
	ok := dnsmessage.Header{ID: id, Response: true}
	soa := rr{"example.test.", dnsmessage.TypeSOA}
	www := rr{"www.example.test.", dnsmessage.TypeA}
	for _, tc := range []struct {
		name    string
		msg     []byte
		records int // records already read before this message
		want    string
		refused bool
	}{
		{name: "other ID", msg: msgWith(t, dnsmessage.Header{ID: id + 1, Response: true}, []rr{soa}), want: "unexpected message"},
		{name: "a query, not a response", msg: msgWith(t, dnsmessage.Header{ID: id}, []rr{soa}), want: "unexpected message"},
		{name: "SERVFAIL", msg: msgWith(t, dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeServerFailure}, nil), want: "ServerFailure"},
		{name: "first record not SOA", msg: msgWith(t, ok, []rr{www, soa}), refused: true},
		{name: "empty answer", msg: msgWith(t, ok, nil), refused: true},
		{name: "past the record cap", msg: msgWith(t, ok, []rr{www}), records: axfrMaxRecords, want: "too many records"},
		{name: "garbage", msg: []byte{0, 42, 0x80}, want: ""},
	} {
		records, soas := tc.records, 1
		_, err := readTransferMessage(tc.msg, id, "example.test", map[string]struct{}{}, &soas, &records)
		switch {
		case err == nil:
			t.Errorf("%s: accepted", tc.name)
		case tc.refused && !errors.Is(err, ErrTransferRefused):
			t.Errorf("%s: err = %v, want ErrTransferRefused", tc.name, err)
		case !tc.refused && !strings.Contains(err.Error(), tc.want):
			t.Errorf("%s: err = %v, want it to contain %q", tc.name, err, tc.want)
		}
	}
}

// tcpServer accepts one connection, reads the AXFR query, and hands the
// query's ID and the connection to serve.
func tcpServer(t *testing.T, serve func(id uint16, conn net.Conn)) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		query, err := readStreamMessage(conn)
		if err != nil || len(query) < 2 {
			return
		}
		serve(binary.BigEndian.Uint16(query), conn)
	}()
	return ln.Addr().String()
}

func writeFramed(conn net.Conn, msg []byte) {
	_, _ = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)) //nolint:gosec // test messages are small
}

func TestTransferFromHostileServers(t *testing.T) {
	soa := rr{"example.test.", dnsmessage.TypeSOA}
	www := rr{"www.example.test.", dnsmessage.TypeA}
	t.Run("stream ends before the closing SOA", func(t *testing.T) {
		addr := tcpServer(t, func(id uint16, conn net.Conn) {
			writeFramed(conn, msgWith(t, dnsmessage.Header{ID: id, Response: true}, []rr{soa, www}))
		})
		if _, err := Transfer(context.Background(), addr, "example.test", 5*time.Second); err == nil || errors.Is(err, ErrTransferRefused) {
			t.Errorf("err = %v, want a failed transfer, not names or a refusal", err)
		}
	})
	t.Run("partial length prefix", func(t *testing.T) {
		addr := tcpServer(t, func(_ uint16, conn net.Conn) { _, _ = conn.Write([]byte{0}) })
		if _, err := Transfer(context.Background(), addr, "example.test", 5*time.Second); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
		}
	})
	t.Run("message shorter than its prefix", func(t *testing.T) {
		addr := tcpServer(t, func(_ uint16, conn net.Conn) { _, _ = conn.Write([]byte{0, 200, 1, 2, 3}) })
		if _, err := Transfer(context.Background(), addr, "example.test", 5*time.Second); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
		}
	})
	t.Run("cancelled mid-transfer", func(t *testing.T) {
		hold := make(chan struct{})
		t.Cleanup(func() { close(hold) })
		addr := tcpServer(t, func(id uint16, conn net.Conn) {
			writeFramed(conn, msgWith(t, dnsmessage.Header{ID: id, Response: true}, []rr{soa, www}))
			<-hold // then nothing more
		})
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(200*time.Millisecond, cancel)
		start := time.Now()
		_, err := Transfer(ctx, addr, "example.test", 10*time.Second)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
		if time.Since(start) > 3*time.Second {
			t.Errorf("Transfer took %v to stop after the cancel", time.Since(start))
		}
	})
}

func TestReadDenial(t *testing.T) {
	const id = 7
	nx := dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeNameError}
	for _, tc := range []struct {
		name string
		msg  []byte
		want Denial
		err  string
	}{
		{"NSEC", msgWith(t, nx, nil, typeNSEC), DenialNSEC, ""},
		{"NSEC3", msgWith(t, nx, nil, typeNSEC3, typeNSEC3), DenialNSEC3, ""},
		{"NSEC wins over NSEC3", msgWith(t, nx, nil, typeNSEC3, typeNSEC), DenialNSEC, ""},
		{"unsigned", msgWith(t, nx, nil, dnsmessage.TypeSOA), DenialNone, ""},
		{"other ID", msgWith(t, dnsmessage.Header{ID: id + 1, Response: true}, nil), "", "unexpected message"},
		{"SERVFAIL", msgWith(t, dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeServerFailure}, nil), "", "ServerFailure"},
		{"garbage", []byte{0, 7, 0x80, 0, 0, 1}, "", ""},
	} {
		got, err := readDenial(tc.msg, id)
		switch {
		case tc.err == "" && tc.want != "" && (err != nil || got != tc.want):
			t.Errorf("%s: %q, %v; want %q", tc.name, got, err, tc.want)
		case tc.want == "" && err == nil:
			t.Errorf("%s: accepted as %q", tc.name, got)
		case tc.want == "" && !strings.Contains(err.Error(), tc.err):
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.err)
		}
	}
}

// FuzzReadTransferMessage: no input makes the transfer parser panic, loop
// or admit a name outside the zone.
func FuzzReadTransferMessage(f *testing.F) {
	ok := dnsmessage.Header{ID: 1, Response: true}
	f.Add(msgWith(f, ok, []rr{{"example.test.", dnsmessage.TypeSOA}, {"www.example.test.", dnsmessage.TypeA}}))
	f.Add(msgWith(f, ok, []rr{{"www.example.test.", dnsmessage.TypeA}}))
	f.Add([]byte{0, 1, 0x80, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, msg []byte) {
		names := map[string]struct{}{}
		soas, records := 0, 0
		_, _ = readTransferMessage(msg, 1, "example.test", names, &soas, &records)
		for n := range names {
			if !strings.HasSuffix(n, ".example.test") {
				t.Errorf("admitted %q, outside the zone", n)
			}
		}
	})
}

// FuzzReadDenial: no input makes the denial parser panic.
func FuzzReadDenial(f *testing.F) {
	f.Add(msgWith(f, dnsmessage.Header{ID: 1, Response: true, RCode: dnsmessage.RCodeNameError}, nil, typeNSEC))
	f.Add([]byte{0, 1, 0x80})
	f.Fuzz(func(_ *testing.T, msg []byte) { _, _ = readDenial(msg, 1) })
}
