package dns

import (
	"context"
	"net"
	"strings"
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
	target := ""
	for _, r := range records {
		if r.Type == "CNAME" {
			target = r.Value
		}
	}
	if target == "" {
		return ""
	}
	provider := TakeoverProvider(target)
	_, outcome := ResolveDomainWithRetry(ctx, resolver, target, timeout, nil, attempts, DefaultTypes)
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
