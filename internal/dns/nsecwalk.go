package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// MaxWalkSteps bounds an NSEC walk (#437): however long the chain, or
// however many new names a server makes up, a walk sends at most this many
// queries.
const MaxWalkSteps = 10_000

// WalkOptions configures WalkNSEC.
type WalkOptions struct {
	// Timeout bounds each query.
	Timeout time.Duration
	// MaxQueries is the most queries the walk sends (-max-queries); 0, or
	// more than MaxWalkSteps, is MaxWalkSteps.
	MaxQueries int
	// Limiter paces the queries (-rate); nil sends them unpaced.
	Limiter *RateLimiter
	// Deadline, when set, is the time after which no query starts
	// (-max-duration).
	Deadline time.Time
	// Skip reports names out of scope (-exclude): they are not returned, and
	// no query is sent for a name Skip rules out. The walk steps past an
	// excluded subtree when it can.
	Skip func(name string) bool
}

// WalkResult is what a walk listed.
type WalkResult struct {
	// Names are the zone's names, relative to it, sorted: every owner name
	// in the chain except the apex, names that are not host names (a
	// wildcard's *) and names Skip rules out.
	Names []string
	// Queries counts the queries sent.
	Queries int64
	// Stop says why the walk ended before the chain led back to the apex;
	// "" when it listed the whole zone.
	Stop string
}

// WalkNSEC lists zone's names by walking its NSEC chain (#437): starting at
// the apex, it asks server ("ip:port"), which should be authoritative for a
// zone signed with plain NSEC, for the name just after the last one listed
// (\000.<owner>), with the DNSSEC OK bit set, and follows the Next Domain
// Name of the NSEC record that proves the name absent, until it leads back to
// the apex. A next name that does not sort after the name asked for (a loop
// or a server that makes names up), or one outside the zone, ends the walk.
// One query per name; a truncated answer is asked again over TCP.
func WalkNSEC(ctx context.Context, server, zone string, o WalkOptions) (res WalkResult) {
	zone = lowerASCII(strings.TrimSuffix(zone, "."))
	limit := o.MaxQueries
	if limit <= 0 || limit > MaxWalkSteps {
		limit = MaxWalkSteps
	}
	names := map[string]struct{}{}
	defer func() {
		for n := range names {
			res.Names = append(res.Names, n)
		}
		sort.Strings(res.Names)
	}()
	owner := zone
	for {
		switch {
		case ctx.Err() != nil:
			res.Stop = ctx.Err().Error()
			return res
		case res.Queries >= int64(limit):
			res.Stop = fmt.Sprintf("it reached its limit of %d queries", limit)
			return res
		case !o.Deadline.IsZero() && !time.Now().Before(o.Deadline):
			res.Stop = "the time budget ran out"
			return res
		}
		qname := walkQueryName(owner, zone, o.Skip)
		if qname == "" {
			res.Stop = "the rest of the chain is out of scope"
			return res
		}
		if err := o.Limiter.Wait(ctx); err != nil {
			res.Stop = err.Error()
			return res
		}
		res.Queries++
		next, err := walkStep(ctx, server, qname, o.Timeout)
		if err != nil {
			res.Stop = err.Error()
			return res
		}
		if next == zone {
			return res // back at the apex: the whole chain
		}
		if !strings.HasSuffix(next, "."+zone) {
			res.Stop = fmt.Sprintf("malformed chain: the record after %s names %s, outside the zone", printable(owner), printable(next))
			return res
		}
		if canonicalCompare(next, qname) <= 0 {
			res.Stop = fmt.Sprintf("malformed chain: the record after %s names %s, which does not sort after it (a loop)", printable(owner), printable(next))
			return res
		}
		owner = next
		if o.Skip != nil && o.Skip(next) {
			continue
		}
		if rel := strings.TrimSuffix(next, "."+zone); hostLabels(rel) {
			names[rel] = struct{}{}
		}
	}
}

// walkQueryName is the name to ask for after owner: \000.<owner>, the first
// name that sorts after it. When skip rules that name out, owner's subtree is
// out of scope, so the walk steps past the subtree of owner, or of its
// closest ancestor below the apex, whose next sibling skip allows:
// <label>\000.<parent> sorts after every name below <label>.<parent>. "" means
// no such name.
func walkQueryName(owner, zone string, skip func(string) bool) string {
	q := "\x00." + owner
	if skip == nil || !skip(q) {
		return q
	}
	for a := owner; a != zone && strings.HasSuffix(a, "."+zone); {
		label, parent, _ := strings.Cut(a, ".")
		if len(label) < 63 {
			if q := label + "\x00." + parent; !skip(q) {
				return q
			}
		}
		a = parent
	}
	return ""
}

// walkStep asks server about qname and returns the Next Domain Name of the
// NSEC record that covers it.
func walkStep(ctx context.Context, server, qname string, timeout time.Duration) (string, error) {
	id := uint16(rand.UintN(1 << 16)) //nolint:gosec // a DNS message ID, not a secret
	query, err := denialQuery(id, qname+".")
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
	return readCoveringNSEC(resp, id, qname)
}

// readCoveringNSEC returns the next name of the NSEC record in msg's
// authority section that covers qname: the one whose owner is the last to
// sort at or before it.
func readCoveringNSEC(msg []byte, id uint16, qname string) (string, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return "", err
	}
	if h.ID != id || !h.Response {
		return "", errors.New("unexpected message")
	}
	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		return "", fmt.Errorf("the server answered %s", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", err
	}
	if err := p.SkipAllAnswers(); err != nil {
		return "", err
	}
	best, bestNext := "", ""
	for {
		rh, err := p.AuthorityHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			if best == "" {
				return "", fmt.Errorf("no NSEC record covers %s", printable(qname))
			}
			return bestNext, nil
		}
		if err != nil {
			return "", err
		}
		if rh.Type != typeNSEC {
			if err := p.SkipAuthority(); err != nil {
				return "", err
			}
			continue
		}
		rr, err := p.UnknownResource()
		if err != nil {
			return "", err
		}
		owner := lowerASCII(strings.TrimSuffix(rh.Name.String(), "."))
		next, err := nsecNext(rr.Data)
		if err != nil {
			return "", err
		}
		// The record that covers qname is the one owned by the closest name
		// at or before it; an answer may also carry others, such as the one
		// proving no wildcard applies. The caller checks its next name.
		if canonicalCompare(owner, qname) <= 0 && (best == "" || canonicalCompare(owner, best) > 0) {
			best, bestNext = owner, next
		}
	}
}

// nsecNext reads the Next Domain Name at the start of NSEC record data:
// uncompressed wire format, lowercased, without the trailing dot.
func nsecNext(data []byte) (string, error) {
	var labels []string
	for off, size := 0, 0; ; {
		if off >= len(data) {
			return "", errors.New("malformed NSEC record")
		}
		n := int(data[off])
		if n == 0 {
			break
		}
		size += n + 1
		if n > 63 || off+1+n > len(data) || size > 254 {
			return "", errors.New("malformed NSEC next name")
		}
		label := string(data[off+1 : off+1+n])
		if strings.Contains(label, ".") {
			return "", errors.New("NSEC next name has a label with a dot in it")
		}
		labels = append(labels, label)
		off += 1 + n
	}
	return lowerASCII(strings.Join(labels, ".")), nil
}

// canonicalCompare orders two lowercase names (no trailing dot) as RFC
// 4034 section 6.1 does: label by label from the right, each label's octets
// compared in turn, and a name sorting before every name below it.
func canonicalCompare(a, b string) int {
	la, lb := splitLabels(a), splitLabels(b)
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := strings.Compare(la[i], lb[j]); c != 0 {
			return c
		}
	}
	return len(la) - len(lb)
}

func splitLabels(name string) []string {
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// lowerASCII lowercases ASCII letters only, as DNS names compare, leaving
// other octets alone.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// hostLabels reports whether rel is made of host-name labels: letters,
// digits, hyphens and underscores.
func hostLabels(rel string) bool {
	if rel == "" {
		return false
	}
	for label := range strings.SplitSeq(rel, ".") {
		if label == "" {
			return false
		}
		for _, c := range []byte(label) {
			ok := 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

// printable shows a name in messages with octets outside printable ASCII
// escaped as \DDD.
func printable(name string) string {
	var b strings.Builder
	for _, c := range []byte(name) {
		if c < '!' || c > '~' {
			fmt.Fprintf(&b, `\%03d`, c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
