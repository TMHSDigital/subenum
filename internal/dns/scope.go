package dns

import (
	"net/netip"
	"slices"
)

// Address scopes that AddressScope and InternalScope report (#218). A public
// name that answers with one of them leaks internal addressing.
const (
	ScopeLoopback    = "loopback"    // 127.0.0.0/8, ::1
	ScopeUnspecified = "unspecified" // 0.0.0.0, ::
	ScopeLinkLocal   = "link-local"  // 169.254.0.0/16, fe80::/10
	ScopePrivate     = "private"     // RFC 1918, fc00::/7
	ScopeCGNAT       = "cgnat"       // 100.64.0.0/10 (RFC 6598 shared address space)
)

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// scopeOrder ranks the scopes, most notable first.
var scopeOrder = []string{ScopeLoopback, ScopeUnspecified, ScopeLinkLocal, ScopePrivate, ScopeCGNAT}

// AddressScope returns the non-public scope of an IPv4 or IPv6 address, or
// "" when it is public or cannot be parsed. IPv4-mapped IPv6 addresses are
// classified as the IPv4 address.
func AddressScope(addr string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return ScopeLoopback
	case a.IsUnspecified():
		return ScopeUnspecified
	case a.IsLinkLocalUnicast():
		return ScopeLinkLocal
	case a.IsPrivate():
		return ScopePrivate
	case cgnatPrefix.Contains(a):
		return ScopeCGNAT
	}
	return ""
}

// InternalScope returns the most notable non-public scope among the A and
// AAAA records (loopback before unspecified, link-local, private and cgnat),
// or "" when every address is public.
func InternalScope(records []Record) string {
	best := len(scopeOrder)
	for _, r := range records {
		if r.Type != "A" && r.Type != "AAAA" {
			continue
		}
		if i := slices.Index(scopeOrder, AddressScope(r.Value)); i >= 0 && i < best {
			best = i
		}
	}
	if best == len(scopeOrder) {
		return ""
	}
	return scopeOrder[best]
}
