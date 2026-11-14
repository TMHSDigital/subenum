package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// maxCNAMEChain bounds how many aliases lookupCNAME follows in one answer.
const maxCNAMEChain = 16

// lookupCNAME sends one CNAME query for name and returns the end of the alias
// chain in the answer, or name itself when it has no CNAME (#249). Go's
// LookupCNAME sends A and AAAA queries and then the CNAME query, which made
// -type A,AAAA,CNAME cost five queries a name instead of three.
//
// The query goes through resolver.Dial, the same path as Go's own lookups, so
// the rate budget, the query counter, REFUSED detection and the UDP, TCP, DoT
// and DoH transports all apply. A truncated UDP answer is asked again over
// TCP. Errors are *net.DNSError values shaped like Go's, so Classify and
// wireBudget.fixErr treat them the same way.
func lookupCNAME(ctx context.Context, resolver *net.Resolver, name string) (string, error) {
	if resolver == nil || resolver.Dial == nil {
		return resolver.LookupCNAME(ctx, name)
	}
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return "", &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	msg, err := cnameExchange(ctx, resolver, "udp", qname)
	if err == nil && msg.Truncated {
		msg, err = cnameExchange(ctx, resolver, "tcp", qname)
	}
	if err != nil {
		return "", dnsErrorFor(ctx, name, err)
	}
	switch msg.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return "", &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	default:
		// SERVFAIL, REFUSED and the rest, as Go reports them; fixErr names
		// REFUSED from the RCODE the connection saw.
		return "", &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: msg.RCode == dnsmessage.RCodeServerFailure}
	}
	return canonicalName(msg, name), nil
}

// canonicalName follows the CNAME records in msg's answer from name, at
// most maxCNAMEChain hops, and returns where the chain ends: name itself
// when it has no alias.
func canonicalName(msg *dnsmessage.Message, name string) string {
	aliases := map[string]string{}
	for _, rr := range msg.Answers {
		if c, ok := rr.Body.(*dnsmessage.CNAMEResource); ok && rr.Header.Type == dnsmessage.TypeCNAME {
			aliases[strings.ToLower(rr.Header.Name.String())] = c.CNAME.String()
		}
	}
	canonical := name
	for range maxCNAMEChain {
		next, ok := aliases[strings.ToLower(canonical)]
		if !ok {
			break
		}
		canonical = next
	}
	return canonical
}

// cnameExchange sends one CNAME query for qname over a connection from
// resolver.Dial and returns the matching reply. On UDP, replies to other
// queries (a pooled socket can hold a late answer to an earlier one) are
// skipped until the deadline.
func cnameExchange(ctx context.Context, resolver *net.Resolver, network string, qname dnsmessage.Name) (*dnsmessage.Message, error) {
	conn, err := resolver.Dial(ctx, network, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	query, err := cnameQuery(id, qname)
	if err != nil {
		return nil, err
	}
	_, packet := conn.(net.PacketConn)
	if !packet {
		// One write with the length prefix, as Go's resolver frames it; the
		// DoH connection takes each write as one message.
		query = append(binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(query)), uint16(len(query))), query...) //nolint:gosec // a one-question query is far under 64 KiB
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		var reply []byte
		if packet {
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			reply = buf[:n]
		} else {
			var lenb [2]byte
			if _, err := io.ReadFull(conn, lenb[:]); err != nil {
				return nil, err
			}
			reply = buf[:binary.BigEndian.Uint16(lenb[:])]
			if _, err := io.ReadFull(conn, reply); err != nil {
				return nil, err
			}
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(reply); err != nil {
			if packet {
				continue // not a DNS message for us
			}
			return nil, err
		}
		if msg.ID != id || !msg.Response || len(msg.Questions) != 1 ||
			msg.Questions[0].Type != dnsmessage.TypeCNAME || !strings.EqualFold(msg.Questions[0].Name.String(), qname.String()) {
			if packet {
				continue // a late answer to an earlier query on this socket
			}
			return nil, errors.New("reply does not match the query")
		}
		return &msg, nil
	}
}

// cnameQuery builds a recursive CNAME query with an EDNS(0) OPT record
// advertising 1232-byte UDP answers, as Go's resolver sends.
func cnameQuery(id uint16, qname dnsmessage.Name) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: qname, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// dnsErrorFor turns a transport error into the *net.DNSError Go's resolver
// would return: a timeout or cancellation keeps its context error, so
// Classify still tells them apart.
func dnsErrorFor(ctx context.Context, name string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return &net.DNSError{Err: ctxErr.Error(), Name: name, IsTimeout: errors.Is(ctxErr, context.DeadlineExceeded), UnwrapErr: ctxErr}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true, IsTemporary: true}
	}
	return &net.DNSError{Err: err.Error(), Name: name, UnwrapErr: err}
}
