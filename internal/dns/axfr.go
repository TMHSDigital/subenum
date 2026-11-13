package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Zone transfer limits (#85). A transfer is one TCP stream of messages; these
// bound what a hostile or broken server can make the client read.
const (
	axfrMaxRecords  = 1 << 20
	axfrMaxMessages = 1 << 16
)

// rcodeNotAuth is NOTAUTH (RFC 2845), which some servers send to refuse a
// transfer; dnsmessage has no constant for it.
const rcodeNotAuth dnsmessage.RCode = 9

// ErrTransferRefused is returned by Transfer when the server answers but
// does not allow a zone transfer, the usual and correct configuration.
var ErrTransferRefused = errors.New("zone transfer refused")

// Transfer asks server ("ip:port") for a full zone transfer (AXFR, RFC 5936)
// of zone over TCP and returns the names in the zone: lowercase, without the
// trailing dot, sorted, without duplicates, and without the apex itself.
// Every record's owner counts, whatever its type. timeout bounds the whole
// transfer, connection included.
func Transfer(ctx context.Context, server, zone string, timeout time.Duration) ([]string, error) {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	id := uint16(rand.UintN(1 << 16)) //nolint:gosec // a DNS message ID, not a secret
	query, err := axfrQuery(id, zone)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	names := map[string]struct{}{}
	soas, records := 0, 0
	for range axfrMaxMessages {
		msg, err := readStreamMessage(conn)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("zone transfer from %s: %w", server, ctx.Err())
			}
			if records == 0 && errors.Is(err, io.EOF) {
				// Closing the connection without an answer is how many
				// servers refuse.
				return nil, ErrTransferRefused
			}
			return nil, fmt.Errorf("zone transfer from %s: %w", server, err)
		}
		done, err := readTransferMessage(msg, id, zone, names, &soas, &records)
		if err != nil || done {
			if err != nil {
				return nil, err
			}
			break
		}
	}
	if soas < 2 {
		return nil, fmt.Errorf("zone transfer from %s ended before the closing SOA", server)
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// axfrQuery is a length-prefixed AXFR query for zone.
func axfrQuery(id uint16, zone string) ([]byte, error) {
	name, err := dnsmessage.NewName(zone + ".")
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(make([]byte, 2, 512), dnsmessage.Header{ID: id})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeAXFR, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	msg, err := b.Finish()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(msg, uint16(len(msg)-2)) //nolint:gosec // a one-question message is far under 64 KiB
	return msg, nil
}

// readStreamMessage reads one length-prefixed DNS message from a stream.
func readStreamMessage(r io.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// readTransferMessage adds the owner names of one transfer message's answers
// under zone to names, and reports whether the closing SOA arrived. The first
// record of a transfer must be the zone's SOA, and the next SOA ends it.
func readTransferMessage(msg []byte, id uint16, zone string, names map[string]struct{}, soas, records *int) (bool, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return false, err
	}
	if hdr.ID != id || !hdr.Response {
		return false, errors.New("zone transfer: unexpected message")
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		if hdr.RCode == dnsmessage.RCodeRefused || hdr.RCode == rcodeNotAuth || hdr.RCode == dnsmessage.RCodeNotImplemented {
			return false, ErrTransferRefused
		}
		return false, fmt.Errorf("zone transfer: %s", hdr.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false, err
	}
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return false, err
		}
		if err := p.SkipAnswer(); err != nil {
			return false, err
		}
		*records++
		if *records > axfrMaxRecords {
			return false, errors.New("zone transfer: too many records")
		}
		if *records == 1 && rh.Type != dnsmessage.TypeSOA {
			// A server that answers the question without a transfer.
			return false, ErrTransferRefused
		}
		if rh.Type == dnsmessage.TypeSOA {
			*soas++
			if *soas == 2 {
				return true, nil
			}
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(rh.Name.String(), "."))
		if name != zone && strings.HasSuffix(name, "."+zone) {
			names[name] = struct{}{}
		}
	}
	if *records == 0 {
		return false, ErrTransferRefused
	}
	return false, nil
}
