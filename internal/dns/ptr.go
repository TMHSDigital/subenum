package dns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// ReverseName returns the name a PTR query for addr asks about:
// d.c.b.a.in-addr.arpa for IPv4, and the 32 reversed nibbles under ip6.arpa
// for IPv6 (#436). An IPv4-mapped IPv6 address is its IPv4 address.
func ReverseName(addr string) (string, error) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return "", err
	}
	a = a.Unmap()
	var b strings.Builder
	if a.Is4() {
		v4 := a.As4()
		for i := len(v4) - 1; i >= 0; i-- {
			fmt.Fprintf(&b, "%d.", v4[i])
		}
		b.WriteString("in-addr.arpa")
		return b.String(), nil
	}
	const hex = "0123456789abcdef"
	v6 := a.As16()
	for i := len(v6) - 1; i >= 0; i-- {
		b.WriteByte(hex[v6[i]&0x0f])
		b.WriteByte('.')
		b.WriteByte(hex[v6[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa")
	return b.String(), nil
}

// LookupPTR asks l.Resolver for the PTR records of addr, once, under one
// rate slot of ctx's limiter, l.Timeout and a wire budget, as one record
// type's lookup in ResolveTypes runs (#436). The names are lower case,
// without the trailing dot.
func (l Lookup) LookupPTR(ctx context.Context, addr string) ([]string, error) {
	if err := limiterFrom(ctx).Wait(ctx); err != nil {
		return nil, err
	}
	b := &wireBudget{prepaid: 1}
	lookupCtx, cancel := context.WithTimeout(context.WithValue(ctx, budgetKey{}, b), l.Timeout)
	defer cancel()
	names, err := l.Resolver.LookupAddr(lookupCtx, addr)
	if err != nil && len(names) == 0 {
		return nil, b.fixErr(err)
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSuffix(n, ".")); n != "" {
			out = append(out, n)
		}
	}
	return out, nil
}

// LookupPTR is Lookup.LookupPTR on one of the pool's healthy members, after
// a slot of its -rate-per-resolver cap. The answer does not count toward the
// member's health: most addresses have no PTR record, which says nothing
// about the resolver.
func (p *Pool) LookupPTR(ctx context.Context, l Lookup, addr string) ([]string, error) {
	m := p.pick(nil)
	if m == nil {
		return nil, fmt.Errorf("no healthy resolver in the pool")
	}
	if err := p.reserve(ctx, m, 1); err != nil {
		return nil, err
	}
	return m.lookup(l).LookupPTR(ctx, addr)
}
