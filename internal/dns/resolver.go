// Package dns resolves candidate names, classifies lookup outcomes, detects
// wildcard zones, paces queries and simulates resolution for -simulate.
package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// Record is a single resolved DNS record. Type is "A", "AAAA", "CNAME", etc.
// Value is the IP address (A/AAAA), the target name (CNAME), the name server
// (NS), "<preference> <host>" (MX) or the text (TXT).
type Record struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// RecordKey identifies a record by type and value, for de-duplication and
// fingerprint matching.
func RecordKey(r Record) string { return r.Type + "\x00" + r.Value }

// DefaultTypes is the record-type set used when none is specified; it preserves
// the historical LookupHost behavior (A and AAAA).
var DefaultTypes = []string{"A", "AAAA"}

var supportedTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "NS": true, "MX": true, "TXT": true}

// SupportedTypes names the record types -type accepts, for messages.
const SupportedTypes = "A, AAAA, CNAME, NS, MX, TXT"

// Outcome is a coarse classification of one resolver attempt so callers can
// tell a definitive negative (NXDOMAIN) apart from an infrastructure failure.
type Outcome int

// Lookup outcomes, from a definitive answer to an interrupted lookup.
const (
	// OutcomeFound means the lookup returned records of a requested type.
	OutcomeFound Outcome = iota
	// OutcomeNXDomain is a definitive negative: the name does not exist, or it
	// exists but has no records of the requested types (NODATA). Go's resolver
	// already reports NODATA as not-found for A/AAAA; CNAME is folded in here too.
	OutcomeNXDomain
	OutcomeTimeout
	OutcomeRefused
	OutcomeOther
	// OutcomeCanceled means the scan context was cancelled mid-lookup. It says
	// nothing about the resolver and must not be counted as a failure.
	OutcomeCanceled
)

// String names an outcome for messages.
func (o Outcome) String() string {
	switch o {
	case OutcomeFound:
		return "found"
	case OutcomeNXDomain:
		return "NXDOMAIN"
	case OutcomeTimeout:
		return "timeout"
	case OutcomeRefused:
		return "refused"
	case OutcomeCanceled:
		return "canceled"
	}
	return "error"
}

// Classify maps a resolver error onto a coarse outcome so callers can tell a
// definitive negative (NXDOMAIN) apart from an infrastructure failure.
func Classify(err error) Outcome {
	if err == nil {
		return OutcomeFound
	}
	if errors.Is(err, context.Canceled) {
		return OutcomeCanceled
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		switch {
		case de.IsNotFound:
			return OutcomeNXDomain
		case de.IsTimeout:
			return OutcomeTimeout
		}
		if strings.Contains(strings.ToLower(de.Err), "refused") {
			return OutcomeRefused
		}
	}
	return OutcomeOther
}

// ParseTypes parses a comma-separated record-type list (for example
// "A,AAAA,CNAME") into a normalized, de-duplicated, uppercase slice.
func ParseTypes(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return append([]string(nil), DefaultTypes...), nil
	}
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(s, ",") {
		t := strings.ToUpper(strings.TrimSpace(part))
		if t == "" {
			continue
		}
		if !supportedTypes[t] {
			return nil, fmt.Errorf("unsupported record type %q (want %s)", part, SupportedTypes)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), DefaultTypes...), nil
	}
	return out, nil
}

// NewResolver returns a PreferGo resolver that always dials dnsServer. The Dial
// hook honors the network argument so a truncated UDP response can fall back to TCP.
//
// Go's resolver dials a fresh connection for every query it sends, including
// its own internal retries (attempts x system nameservers on SERVFAIL, REFUSED
// or socket errors), so each dial is one wire query. Under a lookup started by
// ResolveTypes, a dial beyond the slots reserved up front takes another rate
// slot, which keeps -rate exact however many queries Go decides to send (#50).
func NewResolver(timeout time.Duration, dnsServer string) *net.Resolver {
	dl := newDialer(timeout, dnsServer) // UDP/TCP, DoT or DoH (#86)
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			if c, ok := dialCtx.Value(queryCounterKey{}).(*atomic.Int64); ok {
				c.Add(1)
			}
			b, _ := dialCtx.Value(budgetKey{}).(*wireBudget)
			if b != nil {
				b.server.Store(dnsServer)
				if b.dials.Add(1) > b.prepaid {
					if err := limiterFrom(dialCtx).Wait(dialCtx); err != nil {
						return nil, err
					}
				}
			}
			c, err := dl.dial(dialCtx, network)
			if err != nil || b == nil {
				return c, err
			}
			// Go frames UDP and TCP differently depending on whether the conn
			// is a net.PacketConn, so a UDP wrapper must stay one.
			if u, ok := c.(*pooledUDPConn); ok {
				return &rcodeUDPConn{pooledUDPConn: u, b: b}, nil
			}
			return &rcodeTCPConn{Conn: c, b: b}, nil
		},
	}
	registerDialer(r, dl)
	return r
}

// wireBudget follows one per-type lookup through Go's resolver: the rate
// slots ResolveTypes reserved for it, the queries actually dialed, and whether
// any response carried RCODE REFUSED.
type wireBudget struct {
	prepaid int32
	dials   atomic.Int32
	refused atomic.Bool
	server  atomic.Value // string: the -dns-server actually dialed
}

type budgetKey struct{}

type queryCounterKey struct{}

// WithQueryCounter attaches c to ctx; every DNS query a resolver from
// NewResolver dials under that ctx (retries included) increments it, so a
// scan can report the queries it actually sent (#70).
func WithQueryCounter(ctx context.Context, c *atomic.Int64) context.Context {
	return context.WithValue(ctx, queryCounterKey{}, c)
}

// fixErr rewrites what Go's resolver cannot report: it names the system
// nameserver instead of the one dialed, and reports REFUSED as a generic
// "server misbehaving", hiding the most common rate-limit signal (#50).
func (b *wireBudget) fixErr(err error) error {
	var de *net.DNSError
	if !errors.As(err, &de) {
		return err
	}
	cp := *de
	if s, ok := b.server.Load().(string); ok {
		cp.Server = s
	}
	if b.refused.Load() && Classify(err) == OutcomeOther {
		cp.Err = "server refused the query (REFUSED)"
	}
	return &cp
}

// noteRCode inspects a DNS message header: QR set and RCODE 5 is REFUSED.
func (b *wireBudget) noteRCode(msg []byte) {
	if len(msg) >= 4 && msg[2]&0x80 != 0 && msg[3]&0x0F == 5 {
		b.refused.Store(true)
	}
}

// rcodeUDPConn records a REFUSED response as Go's resolver reads it. Each
// Read returns one whole datagram. The socket is reused between queries
// (#180), so a late answer to an earlier query can arrive first; only a
// reply carrying the ID of a query sent on this conn counts.
type rcodeUDPConn struct {
	*pooledUDPConn
	b   *wireBudget
	ids []uint16 // IDs of the queries written to this conn
}

func (c *rcodeUDPConn) Write(p []byte) (int, error) {
	if len(p) >= 2 {
		c.ids = append(c.ids, binary.BigEndian.Uint16(p))
	}
	return c.pooledUDPConn.Write(p)
}

func (c *rcodeUDPConn) Read(p []byte) (int, error) {
	n, err := c.pooledUDPConn.Read(p)
	if n >= 2 && slices.Contains(c.ids, binary.BigEndian.Uint16(p)) {
		c.b.noteRCode(p[:n])
	}
	return n, err
}

// rcodeTCPConn is rcodeUDPConn for TCP, where the message follows a two-byte
// length prefix and may arrive split across reads.
type rcodeTCPConn struct {
	net.Conn
	b   *wireBudget
	hdr []byte // the first bytes of the stream, until the RCODE is known
}

func (c *rcodeTCPConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if len(c.hdr) < 6 {
		c.hdr = append(c.hdr, p[:min(n, 6-len(c.hdr))]...)
		if len(c.hdr) == 6 {
			c.b.noteRCode(c.hdr[2:])
		}
	}
	return n, err
}

// fqdn makes domain absolute. Without the trailing dot Go's resolver may also
// try every resolv.conf search suffix (and try them first when the name has
// fewer dots than ndots, as in Kubernetes pods), multiplying queries for each
// missing name.
func fqdn(domain string) string {
	if strings.HasSuffix(domain, ".") {
		return domain
	}
	return domain + "."
}

// queriesPerType is how many DNS queries one lookup of each type puts on the
// wire when the first answer is definitive. Go's LookupCNAME sends A, AAAA
// and CNAME queries. These slots are reserved before the lookup's timeout
// starts; anything Go sends beyond them (its own retries) is charged as it is
// dialed (see NewResolver).
var queriesPerType = map[string]int32{"A": 1, "AAAA": 1, "CNAME": 3, "NS": 1, "MX": 1, "TXT": 1}

// QueriesPerName returns the DNS queries reserved for one name across types.
// An empty type list uses DefaultTypes, as Lookup.ResolveTypes does.
func QueriesPerName(types []string) int64 {
	if len(types) == 0 {
		types = DefaultTypes
	}
	var total int64
	for _, typ := range types {
		total += int64(queriesPerType[typ])
	}
	return total
}

// Lookup is how one name is looked up: the resolver, the per-type timeout,
// how many attempts a retried lookup makes, the record types, and the verbose
// logger. Naming the fields keeps a swapped attempts/types argument from
// compiling (#163). The zero value of each field has a meaning: Attempts < 1
// is one attempt, empty Types is DefaultTypes, and a nil Logf discards lines.
type Lookup struct {
	Resolver *net.Resolver
	Timeout  time.Duration
	Attempts int
	Types    []string
	Logf     Logf
}

// ResolveTypes performs one per-type DNS lookup of domain for each of
// l.Types and returns the matching records, the time spent in lookups, and
// the most severe lookup error (if any). It neither retries nor logs. The
// caller should reuse a single *net.Resolver across lookups (see scan.Run).
//
// Each type gets its own timeout, so a slow A answer cannot starve AAAA or
// CNAME. If ctx carries a RateLimiter (see WithLimiter), each type first waits
// for one slot per query it will send; the timeout starts only after that.
func (l Lookup) ResolveTypes(ctx context.Context, domain string) ([]Record, time.Duration, error) {
	resolver, timeout, types := l.Resolver, l.Timeout, l.Types
	if len(types) == 0 {
		types = DefaultTypes
	}
	lim := limiterFrom(ctx)
	name := fqdn(domain)
	var elapsed time.Duration
	var records []Record
	var worstErr error
	for _, t := range types {
		for i := int32(0); i < queriesPerType[t]; i++ {
			if err := lim.Wait(ctx); err != nil {
				return records, elapsed, err
			}
		}
		b := &wireBudget{prepaid: queriesPerType[t]}
		lookupCtx, cancel := context.WithTimeout(context.WithValue(ctx, budgetKey{}, b), timeout)
		start := time.Now()
		recs, err := lookupType(lookupCtx, resolver, name, domain, t)
		elapsed += time.Since(start)
		cancel()
		if err != nil {
			worstErr = worse(worstErr, b.fixErr(err))
			continue
		}
		records = append(records, recs...)
	}
	return records, elapsed, worstErr
}

// worse keeps the more severe of two lookup errors. Any infrastructure failure
// (timeout, refused, SERVFAIL, cancellation) outranks a not-found answer: a name
// is a definitive negative only if every requested type said so. Otherwise an
// A SERVFAIL followed by an AAAA NXDOMAIN would read as NXDOMAIN and never be
// retried (#31).
func worse(cur, next error) error {
	if cur == nil {
		return next
	}
	if Classify(cur) == OutcomeNXDomain && Classify(next) != OutcomeNXDomain {
		return next
	}
	return cur
}

func lookupType(ctx context.Context, resolver *net.Resolver, name, domain, t string) ([]Record, error) {
	switch t {
	case "A", "AAAA":
		network := "ip4"
		if t == "AAAA" {
			network = "ip6"
		}
		ips, err := resolver.LookupIP(ctx, network, name)
		if err != nil {
			return nil, err
		}
		recs := make([]Record, 0, len(ips))
		for _, ip := range ips {
			recs = append(recs, Record{Type: t, Value: ip.String()})
		}
		return recs, nil
	case "CNAME":
		cname, err := resolver.LookupCNAME(ctx, name)
		if err != nil {
			return nil, err
		}
		// LookupCNAME returns the domain itself when there is no CNAME chain.
		if cname != "" && !strings.EqualFold(strings.TrimSuffix(cname, "."), strings.TrimSuffix(domain, ".")) {
			return []Record{{Type: "CNAME", Value: strings.TrimSuffix(cname, ".")}}, nil
		}
	case "NS":
		// NS records exist only where a zone is delegated (#194).
		nss, err := resolver.LookupNS(ctx, name)
		if err != nil {
			return nil, err
		}
		recs := make([]Record, 0, len(nss))
		for _, ns := range nss {
			recs = append(recs, Record{Type: "NS", Value: strings.ToLower(strings.TrimSuffix(ns.Host, "."))})
		}
		return recs, nil
	case "MX":
		mxs, err := resolver.LookupMX(ctx, name)
		if err != nil {
			return nil, err
		}
		recs := make([]Record, 0, len(mxs))
		for _, mx := range mxs {
			recs = append(recs, Record{Type: "MX", Value: fmt.Sprintf("%d %s", mx.Pref, strings.ToLower(strings.TrimSuffix(mx.Host, ".")))})
		}
		return recs, nil
	case "TXT":
		txts, err := resolver.LookupTXT(ctx, name)
		if err != nil {
			return nil, err
		}
		recs := make([]Record, 0, len(txts))
		for _, txt := range txts {
			recs = append(recs, Record{Type: "TXT", Value: txt})
		}
		return recs, nil
	}
	return nil, nil
}

// Logf receives verbose per-lookup lines. The dns package never writes to
// stderr itself, so the caller can serialize these lines with its own output
// (for example the CLI progress line). A nil Logf discards them.
type Logf func(format string, args ...any)

// StderrLogf writes verbose lines straight to stderr, unsynchronized. It is
// the fallback for callers that set scan.Config.Verbose without a Logf.
func StderrLogf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// resolveWithLog wraps ResolveTypes with the verbose per-lookup logging used
// by the CLI, returning the resolved records for the requested types.
func (l Lookup) resolveWithLog(ctx context.Context, domain string) ([]Record, time.Duration, error) {
	records, elapsed, err := l.ResolveTypes(ctx, domain)
	if l.Logf != nil && len(records) > 0 {
		l.Logf("Resolved: %s (%s: %s) in %s", domain, records[0].Type, records[0].Value, elapsed)
	} else if l.Logf != nil {
		l.Logf("Failed to resolve: %s (Error: %v) in %s", domain, err, elapsed)
	}
	return records, elapsed, err
}

// Resolve looks domain up to l.Attempts times (at least once), logging each
// try through l.Logf and respecting ctx cancellation between attempts with a
// linear backoff delay. It returns the resolved records and a classified
// outcome for the last attempt.
func (l Lookup) Resolve(ctx context.Context, domain string) ([]Record, Outcome) {
	maxAttempts := max(l.Attempts, 1)
	last := OutcomeOther
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, OutcomeCanceled
		}
		records, _, err := l.resolveWithLog(ctx, domain)
		if len(records) > 0 {
			return records, OutcomeFound
		}
		last = Classify(err)
		if last == OutcomeFound {
			// Lookup succeeded but produced no records of the requested types
			// (for example -type CNAME on a name with only A records). That is a
			// definitive negative, not a resolver failure (#28).
			last = OutcomeNXDomain
		}
		if last == OutcomeNXDomain || last == OutcomeCanceled {
			return nil, last
		}
		if attempt < maxAttempts-1 {
			select {
			case <-time.After(time.Duration(50*(attempt+1)) * time.Millisecond):
			case <-ctx.Done():
				return nil, OutcomeCanceled
			}
		}
	}
	return nil, last
}

// RandomLabel returns a 32-character random hex label, the kind wildcard
// probes use: a name no real zone contains.
func RandomLabel() string { return randomHex(32) }

// randomHex returns n random hex characters.
func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)[:n]
}

// ErrWildcardInconclusive is returned (wrapped) by CheckWildcard when a probe
// neither resolved nor got a definitive negative, so the zone may or may not
// be a wildcard. Callers must not treat it as "no wildcard" (#47).
var ErrWildcardInconclusive = errors.New("wildcard check inconclusive")

// CheckWildcard probes the domain with two random subdomains, looking up the
// same record types the scan will request (empty means DefaultTypes), so a
// CNAME wildcard is fingerprinted when -type includes CNAME. Each probe is
// tried up to l.Attempts times; probes are not logged (l.Logf is unused). If
// either probe resolves the domain is treated as wildcard (conservative). The
// returned record slice is the union of both probe answers and is the
// fingerprint used to filter later results.
//
// The check is conclusive only when every probe ended found or NXDOMAIN/NODATA.
// Otherwise the error wraps ErrWildcardInconclusive. Returns (isWildcard,
// fingerprint, error).
func (l Lookup) CheckWildcard(ctx context.Context, domain string) (bool, []Record, error) {
	return l.checkWildcard(ctx, domain, 2, false)
}

// Fingerprint probes sizing for FingerprintWildcard (#48).
const (
	fingerprintProbes    = 5   // initial probes
	fingerprintMaxProbes = 128 // hard cap when the answers rotate
)

// FingerprintWildcard is CheckWildcard for the scan root, where the
// fingerprint filters every result. It starts with five probes, and when
// their answers differ (a wildcard served from a rotating CDN or
// load-balancer pool) it keeps probing until the fingerprint has not grown
// for max(8, 4 x its size) consecutive probes, so the whole pool is learned
// rather than the two addresses two probes happened to see (#48).
func (l Lookup) FingerprintWildcard(ctx context.Context, domain string) (bool, []Record, error) {
	return l.checkWildcard(ctx, domain, fingerprintProbes, true)
}

func (l Lookup) checkWildcard(ctx context.Context, domain string, probes int, saturate bool) (bool, []Record, error) {
	if len(l.Types) == 0 {
		l.Types = DefaultTypes
	}
	l.Attempts = max(l.Attempts, 1)
	l.Logf = nil
	attempts := l.Attempts
	var fp []Record
	seen := map[string]struct{}{}
	add := func(recs []Record) (grew bool) {
		for _, r := range recs {
			k := RecordKey(r)
			if _, ok := seen[k]; !ok {
				seen[k] = struct{}{}
				fp = append(fp, r)
				grew = true
			}
		}
		return grew
	}
	probe := func() error {
		recs, o := l.Resolve(ctx, RandomLabel()+"."+domain)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if o != OutcomeFound && o != OutcomeNXDomain {
			return fmt.Errorf("%w for %s: probe lookup failed (%s) after %d attempt(s)", ErrWildcardInconclusive, domain, o, attempts)
		}
		add(recs)
		return nil
	}

	firstSize := -1
	for i := 0; i < probes; i++ {
		if err := probe(); err != nil {
			return false, nil, err
		}
		if firstSize < 0 {
			firstSize = len(fp)
		}
	}
	if len(fp) == 0 {
		return false, nil, nil
	}
	// The fingerprint grew after the first probe, so the answers rotate.
	if saturate && len(fp) > firstSize {
		stale := 0
		for n := probes; n < fingerprintMaxProbes && stale < max(8, 4*len(fp)); n++ {
			before := len(fp)
			if err := probe(); err != nil {
				return false, nil, err
			}
			if len(fp) > before {
				stale = 0
			} else {
				stale++
			}
		}
	}
	return true, fp, nil
}
