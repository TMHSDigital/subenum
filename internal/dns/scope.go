package dns

import "net/netip"

// Scopes of an address that is not publicly routable (#218). A public name
// that resolves to one of them leaks the internal network layout, and a
// loopback answer can matter for DNS rebinding.
const (
	ScopePrivate   = "private"
	ScopeLoopback  = "loopback"
	ScopeLinkLocal = "link-local"
	ScopeCGNAT     = "cgnat"
)

// cgnat is the carrier-grade NAT range 100.64.0.0/10. netip's IsPrivate does
// not cover it, so it is checked on its own.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// AddressScope classifies an address: it returns the scope name for an
// address that is not publicly routable, and "" for a public one. An address
// that does not parse has no scope either.
func AddressScope(addr string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	// An IPv4-mapped IPv6 address (::ffff:10.0.0.1) is judged as the IPv4
	// address it carries.
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return ScopeLoopback
	case a.IsLinkLocalUnicast():
		return ScopeLinkLocal
	case a.IsPrivate():
		return ScopePrivate
	case cgnat.Contains(a):
		return ScopeCGNAT
	}
	return ""
}

// InternalScope returns the scope of the first internal address among the A
// and AAAA records, or "" when the name resolved to public addresses only.
// CNAME records are skipped: only their target's address would say anything
// about the scope, and the target is not part of the result.
func InternalScope(records []Record) string {
	for _, r := range records {
		if r.Type != "A" && r.Type != "AAAA" {
			continue
		}
		if s := AddressScope(r.Value); s != "" {
			return s
		}
	}
	return ""
}
