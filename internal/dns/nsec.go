package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSSEC denial-of-existence record types; dnsmessage has no constants for
// them.
const (
	typeNSEC  dnsmessage.Type = 47
	typeNSEC3 dnsmessage.Type = 50
)

// Denial is how a zone proves that a name does not exist (#234).
type Denial string

// Denial values.
const (
	DenialNone  Denial = "none"  // no DNSSEC proof: an unsigned zone
	DenialNSEC  Denial = "nsec"  // plain NSEC: the zone can be walked to list every name
	DenialNSEC3 Denial = "nsec3" // hashed NSEC3: not walkable this way
)

// ProbeDenial asks server ("ip:port"), which should be authoritative for
// zone, about a random name that does not exist, with the DNSSEC OK bit
// set, and reports which denial-of-existence records come back. A zone
// signed with plain NSEC can be walked to list every name. It sends one
// query over UDP, and one more over TCP if the answer was truncated.
func ProbeDenial(ctx context.Context, server, zone string, timeout time.Duration) (Denial, error) {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	name := RandomLabel() + "." + zone + "."
	id := uint16(rand.UintN(1 << 16)) //nolint:gosec // a DNS message ID, not a secret
	query, err := denialQuery(id, name)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := exchange(ctx, "udp", server, query)
	if err != nil {
		return "", err
	}
	if truncated(resp) {
		if resp, err = exchange(ctx, "tcp", server, query); err != nil {
			return "", err
		}
	}
	return readDenial(resp, id)
}

// denialQuery is an A query for name, recursion not desired, with an EDNS0
// OPT record asking for DNSSEC records.
func denialQuery(id uint16, name string) ([]byte, error) {
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(4096, dnsmessage.RCodeSuccess, true); err != nil {
		return nil, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// exchange sends query over network ("udp" or "tcp") and returns the reply.
func exchange(ctx context.Context, network, server string, query []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if network == "tcp" {
		msg := binary.BigEndian.AppendUint16(nil, uint16(len(query))) //nolint:gosec // a one-question query is far under 64 KiB
		if _, err := conn.Write(append(msg, query...)); err != nil {
			return nil, err
		}
		return readStreamMessage(conn)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func truncated(msg []byte) bool {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	return err == nil && h.Truncated
}

// readDenial reports which denial records an answer's authority section
// carries.
func readDenial(msg []byte, id uint16) (Denial, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return "", err
	}
	if h.ID != id || !h.Response {
		return "", errors.New("denial probe: unexpected message")
	}
	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		return "", fmt.Errorf("denial probe: %s", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", err
	}
	if err := p.SkipAllAnswers(); err != nil {
		return "", err
	}
	denial := DenialNone
	for {
		rh, err := p.AuthorityHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return denial, nil
		}
		if err != nil {
			return "", err
		}
		if err := p.SkipAuthority(); err != nil {
			return "", err
		}
		switch rh.Type {
		case typeNSEC:
			return DenialNSEC, nil
		case typeNSEC3:
			denial = DenialNSEC3
		}
	}
}
