// Package ct looks up subdomain names in Certificate Transparency logs
// through crt.sh (#130). Certificates name the hosts they cover, so CT shows
// real naming conventions (and forgotten hosts) without an API key. The
// names are only candidates: a scan still has to resolve them.
package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// DefaultURL is crt.sh's search endpoint.
const DefaultURL = "https://crt.sh/"

// maxBody bounds the response: a large organisation's history runs to tens
// of megabytes.
const maxBody = 64 << 20

// Client fetches CT names. The zero value uses DefaultURL and
// http.DefaultClient.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
	Timeout   time.Duration // per lookup; 0 means 60s
}

type entry struct {
	NameValue string `json:"name_value"`
}

// Names returns the names under domain that appear in CT logs, relative to
// it ("api", "dev.api"), sorted and deduplicated. Wildcard entries give
// their parent ("*.dev" gives "dev"); the domain itself, names outside it
// and invalid names are dropped.
func (c Client) Names(ctx context.Context, domain string) ([]string, error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultURL
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	q := url.Values{"q": {"%." + domain}, "output": {"json"}, "deduplicate": {"Y"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certificate transparency lookup: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate transparency lookup: %s returned %s", req.URL.Host, resp.Status)
	}
	var entries []entry
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&entries); err != nil {
		return nil, fmt.Errorf("certificate transparency lookup: reading %s's answer: %w", req.URL.Host, err)
	}
	return relativeNames(entries, domain), nil
}

func relativeNames(entries []entry, domain string) []string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	set := map[string]bool{}
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
			name = strings.TrimPrefix(name, "*.")
			rel, ok := strings.CutSuffix(name, "."+domain)
			if !ok || rel == "" {
				continue
			}
			if norm, ok := wordlist.Normalize(rel); ok {
				set[norm] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
