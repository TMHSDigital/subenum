package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// takeoverProviders maps CNAME target suffixes to services where a dangling
// record has historically allowed a subdomain takeover (after the public
// can-i-take-over-xyz list). A match is only a hint: many such CNAMEs are
// perfectly healthy, and the provider's own response has to be checked by
// hand (#71).
var takeoverProviders = []struct{ suffix, name string }{
	{".s3.amazonaws.com", "aws-s3"},
	{".s3-website.amazonaws.com", "aws-s3"},
	{".elasticbeanstalk.com", "aws-elasticbeanstalk"},
	{".cloudfront.net", "aws-cloudfront"},
	{".azurewebsites.net", "azure"},
	{".cloudapp.net", "azure"},
	{".cloudapp.azure.com", "azure"},
	{".trafficmanager.net", "azure"},
	{".blob.core.windows.net", "azure"},
	{".azureedge.net", "azure"},
	{".azurefd.net", "azure"},
	{".github.io", "github-pages"},
	{".herokuapp.com", "heroku"},
	{".herokudns.com", "heroku"},
	{".fastly.net", "fastly"},
	{".myshopify.com", "shopify"},
	{".ghost.io", "ghost"},
	{".surge.sh", "surge"},
	{".bitbucket.io", "bitbucket"},
	{".pantheonsite.io", "pantheon"},
	{".zendesk.com", "zendesk"},
	{".netlify.app", "netlify"},
	{".netlify.com", "netlify"},
	{".wordpress.com", "wordpress"},
	{".helpscoutdocs.com", "helpscout"},
	{".unbouncepages.com", "unbounce"},
	{".webflow.io", "webflow"},
	{".ngrok.io", "ngrok"},
	{".readme.io", "readme"},
	{".agilecrm.com", "agilecrm"},
	{".canny.io", "canny"},
}

// TakeoverProvider returns the takeover-prone service a CNAME target belongs
// to, or "" when it matches none.
func TakeoverProvider(target string) string {
	t := "." + strings.ToLower(strings.TrimSuffix(target, "."))
	for _, p := range takeoverProviders {
		if strings.HasSuffix(t, p.suffix) {
			return p.name
		}
	}
	return ""
}

// TakeoverHint inspects a result's CNAME records and returns a takeover
// marker: "dangling" when the CNAME target does not resolve (NXDOMAIN),
// "provider:<name>" when it points at a takeover-prone service, and
// "dangling:<name>" when both hold. It returns "" when there is no CNAME or
// nothing suspicious. The target is resolved with resolver; an inconclusive
// lookup (timeout, SERVFAIL) is not called dangling.
func TakeoverHint(ctx context.Context, resolver *net.Resolver, records []Record, timeout time.Duration, attempts int) string {
	target := cnameTarget(records)
	if target == "" {
		return ""
	}
	_, outcome := ResolveDomainWithRetry(ctx, resolver, target, timeout, nil, attempts, DefaultTypes)
	return takeoverMarker(target, outcome)
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

// takeoverMarker turns a CNAME target and its lookup outcome into a hint.
func takeoverMarker(target string, outcome Outcome) string {
	provider := TakeoverProvider(target)
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
func (c *TakeoverCache) Hint(ctx context.Context, resolver *net.Resolver, records []Record, timeout time.Duration, attempts int) string {
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
			_, e.outcome = ResolveDomainWithRetry(ctx, resolver, target, timeout, nil, attempts, DefaultTypes)
			if e.outcome != OutcomeFound && e.outcome != OutcomeNXDomain {
				c.mu.Lock()
				delete(c.entries, key) // inconclusive: let a later name retry
				c.mu.Unlock()
			}
			close(e.done)
			return takeoverMarker(target, e.outcome)
		}
		c.mu.Unlock()
		select {
		case <-e.done:
		case <-ctx.Done():
			return takeoverMarker(target, OutcomeCanceled)
		}
		if e.outcome == OutcomeFound || e.outcome == OutcomeNXDomain {
			return takeoverMarker(target, e.outcome)
		}
		// The shared lookup was inconclusive and dropped; try again.
		if ctx.Err() != nil {
			return takeoverMarker(target, OutcomeCanceled)
		}
	}
}
