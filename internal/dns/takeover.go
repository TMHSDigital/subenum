package dns

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/TMHSDigital/subenum/internal/validate"
)

// ProviderSuffix maps CNAME targets under Suffix (".example-cdn.net") to a
// takeover-prone service Name ("example-cdn").
type ProviderSuffix struct {
	Suffix string
	Name   string
}

// TakeoverProviders is a list of takeover-prone services, matched by the
// longest CNAME target suffix. nil means the built-in list.
type TakeoverProviders []ProviderSuffix

// builtinProviders maps CNAME target suffixes to services where a dangling
// record has historically allowed a subdomain takeover (after the public
// can-i-take-over-xyz list). A match is only a hint: many such CNAMEs are
// perfectly healthy, and the provider's own response has to be checked by
// hand (#71).
var builtinProviders = TakeoverProviders{
	{Suffix: ".s3.amazonaws.com", Name: "aws-s3"},
	{Suffix: ".s3-website.amazonaws.com", Name: "aws-s3"},
	{Suffix: ".elasticbeanstalk.com", Name: "aws-elasticbeanstalk"},
	{Suffix: ".cloudfront.net", Name: "aws-cloudfront"},
	{Suffix: ".azurewebsites.net", Name: "azure"},
	{Suffix: ".cloudapp.net", Name: "azure"},
	{Suffix: ".cloudapp.azure.com", Name: "azure"},
	{Suffix: ".trafficmanager.net", Name: "azure"},
	{Suffix: ".blob.core.windows.net", Name: "azure"},
	{Suffix: ".azureedge.net", Name: "azure"},
	{Suffix: ".azurefd.net", Name: "azure"},
	{Suffix: ".github.io", Name: "github-pages"},
	{Suffix: ".herokuapp.com", Name: "heroku"},
	{Suffix: ".herokudns.com", Name: "heroku"},
	{Suffix: ".fastly.net", Name: "fastly"},
	{Suffix: ".myshopify.com", Name: "shopify"},
	{Suffix: ".ghost.io", Name: "ghost"},
	{Suffix: ".surge.sh", Name: "surge"},
	{Suffix: ".bitbucket.io", Name: "bitbucket"},
	{Suffix: ".pantheonsite.io", Name: "pantheon"},
	{Suffix: ".zendesk.com", Name: "zendesk"},
	{Suffix: ".netlify.app", Name: "netlify"},
	{Suffix: ".netlify.com", Name: "netlify"},
	{Suffix: ".wordpress.com", Name: "wordpress"},
	{Suffix: ".helpscoutdocs.com", Name: "helpscout"},
	{Suffix: ".unbouncepages.com", Name: "unbounce"},
	{Suffix: ".webflow.io", Name: "webflow"},
	{Suffix: ".ngrok.io", Name: "ngrok"},
	{Suffix: ".readme.io", Name: "readme"},
	{Suffix: ".agilecrm.com", Name: "agilecrm"},
	{Suffix: ".canny.io", Name: "canny"},
	{Suffix: ".animaapp.io", Name: "anima"},
	{Suffix: ".trydiscourse.com", Name: "discourse"},
}

// DefaultTakeoverProviders returns a copy of the built-in list.
func DefaultTakeoverProviders() TakeoverProviders { return slices.Clone(builtinProviders) }

// TakeoverProvider returns the built-in takeover-prone service a CNAME target
// belongs to, or "" when it matches none.
func TakeoverProvider(target string) string { return TakeoverProviders(nil).Match(target) }

// Match returns the service a CNAME target belongs to, or "" when it matches
// none. When several suffixes match, the longest wins, so a narrower entry
// overrides a broader one. A nil list matches the built-in providers.
func (p TakeoverProviders) Match(target string) string {
	if p == nil {
		p = builtinProviders
	}
	t := "." + strings.ToLower(strings.TrimSuffix(target, "."))
	name, best := "", 0
	for _, e := range p {
		if len(e.Suffix) > best && strings.HasSuffix(t, e.Suffix) {
			name, best = e.Name, len(e.Suffix)
		}
	}
	return name
}

// providerName is a provider as it may appear in a marker and a SARIF rule
// id: lowercase letters, digits and inner hyphens.
var providerName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ParseTakeoverProviders reads a -takeover-providers file (#219): one
// "<suffix> <name>" pair per line, such as ".example-cdn.net example-cdn",
// with blank lines and # comments ignored. The suffix may omit its leading
// dot and may be an IDN. A name of "-" removes that suffix instead. Unless
// only is set, the entries extend (or, for a suffix already listed, replace)
// the built-in list. Errors name the 1-based line.
func ParseTakeoverProviders(lines []string, only bool) (TakeoverProviders, error) {
	var out TakeoverProviders
	if !only {
		out = DefaultTakeoverProviders()
	}
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: want \"<suffix> <name>\", got %q", i+1, line)
		}
		raw, name := strings.TrimPrefix(fields[0], "."), fields[1]
		if strings.ContainsAny(raw, "/:?#@*") {
			return nil, fmt.Errorf("line %d: %q is not a domain suffix", i+1, fields[0])
		}
		domain, _, err := validate.NormalizeDomain(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		suffix := "." + domain
		out = slices.DeleteFunc(out, func(e ProviderSuffix) bool { return e.Suffix == suffix })
		if name == "-" {
			continue
		}
		if !providerName.MatchString(name) {
			return nil, fmt.Errorf("line %d: provider name %q must be lowercase letters, digits and hyphens", i+1, name)
		}
		out = append(out, ProviderSuffix{Suffix: suffix, Name: name})
	}
	if out == nil {
		out = TakeoverProviders{} // an empty -only list matches nothing, unlike nil
	}
	return out, nil
}

// TakeoverHint inspects a result's CNAME records and returns a takeover
// marker: "dangling" when the CNAME target does not resolve (NXDOMAIN),
// "provider:<name>" when it points at a takeover-prone service, and
// "dangling:<name>" when both hold. It returns "" when there is no CNAME or
// nothing suspicious. The target is resolved with l.Resolver, l.Timeout and
// l.Attempts for DefaultTypes, without logging (l.Types and l.Logf are
// unused); an inconclusive lookup (timeout, SERVFAIL) is not called dangling.
func TakeoverHint(ctx context.Context, l Lookup, records []Record) string {
	target := cnameTarget(records)
	if target == "" {
		return ""
	}
	_, outcome := l.forTarget().Resolve(ctx, target)
	return TakeoverProviders(nil).marker(target, outcome)
}

// forTarget is l as a CNAME target lookup: DefaultTypes, no logging.
func (l Lookup) forTarget() Lookup {
	l.Types, l.Logf = DefaultTypes, nil
	return l
}

// cnameTarget returns the CNAME target among records, or "".
func cnameTarget(records []Record) string {
	target := ""
	for _, r := range records {
		if r.Type == "CNAME" {
			target = r.Value
		}
	}
	return target
}

// marker turns a CNAME target and its lookup outcome into a hint.
func (p TakeoverProviders) marker(target string, outcome Outcome) string {
	provider := p.Match(target)
	switch {
	case outcome == OutcomeNXDomain && provider != "":
		return "dangling:" + provider
	case outcome == OutcomeNXDomain:
		return "dangling"
	case provider != "":
		return "provider:" + provider
	}
	return ""
}

// TakeoverCache is TakeoverHint with one lookup per CNAME target for the
// life of the cache (a scan): many names aliased to the same CDN or SaaS
// host cost one query and one rate slot, not one each (#121). Concurrent
// callers for the same target share the lookup. An inconclusive outcome
// (timeout, SERVFAIL, cancellation) is not kept, so a later name retries.
type TakeoverCache struct {
	// Providers are the takeover-prone services to match; nil is the
	// built-in list (#219).
	Providers TakeoverProviders

	mu      sync.Mutex
	entries map[string]*takeoverEntry
	lookups atomic.Int64
}

type takeoverEntry struct {
	done    chan struct{}
	outcome Outcome
}

// Lookups reports how many target lookups the cache sent.
func (c *TakeoverCache) Lookups() int64 { return c.lookups.Load() }

// Hint is TakeoverHint through the cache.
func (c *TakeoverCache) Hint(ctx context.Context, l Lookup, records []Record) string {
	target := cnameTarget(records)
	if target == "" {
		return ""
	}
	key := strings.ToLower(strings.TrimSuffix(target, "."))
	for {
		c.mu.Lock()
		if c.entries == nil {
			c.entries = map[string]*takeoverEntry{}
		}
		e, ok := c.entries[key]
		if !ok {
			e = &takeoverEntry{done: make(chan struct{})}
			c.entries[key] = e
			c.mu.Unlock()
			c.lookups.Add(1)
			_, e.outcome = l.forTarget().Resolve(ctx, target)
			if e.outcome != OutcomeFound && e.outcome != OutcomeNXDomain {
				c.mu.Lock()
				delete(c.entries, key) // inconclusive: let a later name retry
				c.mu.Unlock()
			}
			close(e.done)
			return c.Providers.marker(target, e.outcome)
		}
		c.mu.Unlock()
		select {
		case <-e.done:
		case <-ctx.Done():
			return c.Providers.marker(target, OutcomeCanceled)
		}
		if e.outcome == OutcomeFound || e.outcome == OutcomeNXDomain {
			return c.Providers.marker(target, e.outcome)
		}
		// The shared lookup was inconclusive and dropped; try again.
		if ctx.Err() != nil {
			return c.Providers.marker(target, OutcomeCanceled)
		}
	}
}
