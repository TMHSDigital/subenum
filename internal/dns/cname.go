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
	// NewName checks only the 255-byte total; a label of 0 or over 63 bytes
	// fails later, when the query is built, after a dial, a rate slot and a
	// counted query (#344). No such name can exist, so neither is asked.
	qname, err := dnsmessage.NewName(name)
	if err != nil || !validLabels(name) {
		return "", &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	msg, err := rawLookup(ctx, resolver, name, qname, dnsmessage.TypeCNAME)
	if err != nil {
		return "", err
	}
	target := canonicalName(msg, name)
	if !validTarget(target) {
		// Go's own lookups refuse such an answer with this error.
		return "", &net.DNSError{Err: "DNS response contained records which contain invalid names", Name: name}
	}
	return target, nil
}

// validTarget reports whether name, which may end in a dot, is a host name
// in presentation form: labels of 1 to 63 letters, digits, hyphens or
// underscores, 253 bytes at most. dnsmessage hands back a name's raw bytes,
// so a hostile answer could otherwise carry control bytes into results.
func validTarget(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 || !validLabels(name) {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c != '.' && c != '-' && c != '_' && (c < '0' || c > '9') && (c|0x20 < 'a' || c|0x20 > 'z') {
			return false
		}
	}
	return true
}

// rawLookup sends one qtype query for name over resolver.Dial, asking again
// over TCP when the UDP answer is truncated, and returns a NOERROR answer.
// Any other RCODE comes back as the *net.DNSError Go's resolver would give.
func rawLookup(ctx context.Context, resolver *net.Resolver, name string, qname dnsmessage.Name, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
	msg, err := cnameExchange(ctx, resolver, "udp", qname, qtype)
	if err == nil && msg.Truncated {
		msg, err = cnameExchange(ctx, resolver, "tcp", qname, qtype)
	}
	if err != nil {
		return nil, dnsErrorFor(ctx, name, err)
	}
	switch msg.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	default:
		// SERVFAIL, REFUSED and the rest, as Go reports them; fixErr names
		// REFUSED from the RCODE the connection saw.
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: msg.RCode == dnsmessage.RCodeServerFailure}
	}
	return msg, nil
}

// nameExists sends one A query for name and returns nil when the answer is
// NOERROR, with or without addresses: the name, or the end of its alias
// chain, exists (#362). Go's resolver reports NODATA as not-found, the same
// as NXDOMAIN; only RCODE 3 comes back here as a not-found error.
func nameExists(ctx context.Context, resolver *net.Resolver, name string) error {
	if resolver == nil || resolver.Dial == nil {
		_, err := resolver.LookupIPAddr(ctx, name)
		return err
	}
	qname, err := dnsmessage.NewName(name)
	if err != nil || !validLabels(name) {
		return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	_, err = rawLookup(ctx, resolver, name, qname, dnsmessage.TypeA)
	return err
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

// cnameExchange sends one qtype query (CNAME for lookupCNAME) for qname over
// a connection from resolver.Dial and returns the matching reply. On UDP,
// replies to other queries (a pooled socket can hold a late answer to an
// earlier one) are skipped until the deadline, and an answer cut to the read
// buffer comes back marked truncated.
func cnameExchange(ctx context.Context, resolver *net.Resolver, network string, qname dnsmessage.Name, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
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
	query, err := cnameQuery(id, qname, qtype)
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
	// A UDP answer is at most the payload the query advertises, as in Go's
	// resolver; a stream answer gets exactly the length its prefix gives. No
	// 64 KiB buffer per lookup (#321).
	var buf []byte
	if packet {
		buf = make([]byte, ednsPayload)
	}
	for {
		var reply []byte
		cut := false
		if packet {
			n, err := conn.Read(buf)
			// A datagram longer than buf is cut to fit: silently on Linux,
			// with WSAEMSGSIZE on Windows. Its header is still there to match.
			if err != nil && n < len(buf) {
				return nil, err
			}
			reply, cut = buf[:n], n == len(buf)
		} else {
			var lenb [2]byte
			if _, err := io.ReadFull(conn, lenb[:]); err != nil {
				return nil, err
			}
			reply = make([]byte, binary.BigEndian.Uint16(lenb[:]))
			if _, err := io.ReadFull(conn, reply); err != nil {
				return nil, err
			}
		}
		h, ok := replyMatches(reply, id, qname, qtype)
		if !ok {
			if packet {
				continue // a late answer to an earlier query on this socket, or not DNS
			}
			return nil, errors.New("reply does not match the query")
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(reply); err != nil {
			if cut {
				// The server ignored the advertised size and did not set TC:
				// ask again over TCP as if it had, rather than skip the
				// answer and wait out the deadline (#375).
				h.Truncated = true
				return &dnsmessage.Message{Header: h}, nil
			}
			return nil, err
		}
		return &msg, nil
	}
}

// replyMatches reports whether reply answers the query with this ID, name
// and type, reading only its header and question, and returns the header.
func replyMatches(reply []byte, id uint16, qname dnsmessage.Name, qtype dnsmessage.Type) (dnsmessage.Header, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil || h.ID != id || !h.Response {
		return h, false
	}
	q, err := p.Question()
	if err != nil || q.Type != qtype || !strings.EqualFold(q.Name.String(), qname.String()) {
		return h, false
	}
	_, err = p.Question()
	return h, errors.Is(err, dnsmessage.ErrSectionDone) // exactly one question
}

// ednsPayload is the UDP answer size cnameQuery advertises, Go's resolver's.
const ednsPayload = 1232

// validLabels reports whether every label of name, which may end in a dot,
// is 1 to 63 bytes long.
func validLabels(name string) bool {
	for label := range strings.SplitSeq(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
	}
	return true
}

// cnameQuery builds a recursive qtype query with an EDNS(0) OPT record
// advertising 1232-byte UDP answers, as Go's resolver sends.
func cnameQuery(id uint16, qname dnsmessage.Name, qtype dnsmessage.Type) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: qname, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(ednsPayload, dnsmessage.RCodeSuccess, false); err != nil {
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
