package dns

import (
	"context"
	"encoding/binary"
	"net"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// lookupHTTPS sends one HTTPS query (RFC 9460, type 65) for name and returns
// its records as "<priority> <target> [alpn=<ids>] [port=<n>]" (#438). Go's
// resolver has no HTTPS lookup, so the query goes through rawLookup over
// resolver.Dial, like lookupCNAME: the rate budget, the query counter,
// REFUSED detection and every transport apply. When name is an alias, the
// records of the end of the chain in the answer are the ones reported, as Go
// reports for the types it looks up. A NOERROR answer without HTTPS records
// (NODATA) is a not-found error, as Go reports it for other types.
func lookupHTTPS(ctx context.Context, resolver *net.Resolver, name string) ([]Record, error) {
	if resolver == nil || resolver.Dial == nil {
		return nil, &net.DNSError{Err: "HTTPS lookups need a resolver from NewResolver", Name: name}
	}
	qname, err := dnsmessage.NewName(name)
	if err != nil || !validLabels(name) {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	msg, err := rawLookup(ctx, resolver, name, qname, dnsmessage.TypeHTTPS)
	if err != nil {
		return nil, err
	}
	owner := canonicalName(msg, name)
	var recs []Record
	for _, rr := range msg.Answers {
		h, ok := rr.Body.(*dnsmessage.HTTPSResource)
		if !ok || rr.Header.Type != dnsmessage.TypeHTTPS || !strings.EqualFold(rr.Header.Name.String(), owner) {
			continue
		}
		v, ok := formatHTTPS(h.SVCBResource)
		if !ok {
			// Go's own lookups refuse such an answer with this error.
			return nil, &net.DNSError{Err: "DNS response contained records which contain invalid names", Name: name}
		}
		if r := (Record{Type: "HTTPS", Value: v}); !slices.Contains(recs, r) {
			recs = append(recs, r)
		}
	}
	if len(recs) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	// The answer's order is the server's; sorted, the same answer always
	// reads the same, so -diff-records sees no change.
	slices.SortFunc(recs, func(a, b Record) int { return strings.Compare(a.Value, b.Value) })
	return recs, nil
}

// formatHTTPS writes an HTTPS record as "<priority> <target>", followed in
// ServiceMode (priority above 0) by its alpn and port parameters, if any:
// "1 . alpn=h2,h3 port=443". The target is lower case without its trailing
// dot, or "." (in AliasMode: the service is not offered; in ServiceMode:
// the owner name itself). Other parameters (address hints, ECH keys) are
// left out: they change often and would make -diff-records noisy. ok is
// false when the target is not a host name.
func formatHTTPS(r dnsmessage.SVCBResource) (string, bool) {
	target := r.Target.String()
	if target != "." {
		if !validTarget(target) {
			return "", false
		}
		target = strings.ToLower(strings.TrimSuffix(target, "."))
	}
	parts := []string{strconv.Itoa(int(r.Priority)), target}
	if r.Priority == 0 {
		// RFC 9460 section 2.4.2: an AliasMode record's parameters are
		// ignored.
		return strings.Join(parts, " "), true
	}
	if v, ok := r.GetParam(dnsmessage.SVCParamALPN); ok {
		if ids, ok := alpnIDs(v); ok {
			parts = append(parts, "alpn="+strings.Join(ids, ","))
		}
	}
	if v, ok := r.GetParam(dnsmessage.SVCParamPort); ok && len(v) == 2 {
		parts = append(parts, "port="+strconv.Itoa(int(binary.BigEndian.Uint16(v))))
	}
	return strings.Join(parts, " "), true
}

// alpnIDs decodes an alpn parameter, a list of length-prefixed protocol IDs,
// with each ID escaped as a TXT text is, and a comma or a space in it
// written as \044 or \032, so the list reads back unambiguously. Whoever
// runs the scanned zone writes these bytes. ok is false for an empty or
// malformed list.
func alpnIDs(v []byte) ([]string, bool) {
	var ids []string
	for len(v) > 0 {
		n := int(v[0])
		if n == 0 || len(v) < 1+n {
			return nil, false
		}
		id := EscapeTXT(string(v[1 : 1+n]))
		id = strings.NewReplacer(",", `\044`, " ", `\032`).Replace(id)
		ids = append(ids, id)
		v = v[1+n:]
	}
	return ids, len(ids) > 0
}

// HTTPSTarget returns the target host of an HTTPS record ("<priority>
// <target> ..."), or "" for another type or a "." target, which names no
// other host (#438).
func HTTPSTarget(r Record) string {
	if r.Type != "HTTPS" {
		return ""
	}
	fields := strings.Fields(r.Value)
	if len(fields) < 2 || fields[1] == "." {
		return ""
	}
	return strings.TrimSuffix(fields[1], ".")
}

// httpsAliasTarget returns the target of an AliasMode HTTPS record (priority
// 0) among records, or "". Such a record points the name at another host
// the way a CNAME does (#438).
func httpsAliasTarget(records []Record) string {
	for _, r := range records {
		if target := HTTPSTarget(r); target != "" && strings.HasPrefix(r.Value, "0 ") {
			return target
		}
	}
	return ""
}
