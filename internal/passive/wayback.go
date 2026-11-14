package passive

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TMHSDigital/subenum/internal/retryhttp"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// WaybackURL is the Wayback Machine's CDX index endpoint.
const WaybackURL = "https://web.archive.org/cdx/search/cdx"

// Wayback bounds: a long-lived domain has millions of archived URLs, and
// the index returns them one per line.
const (
	waybackLimit   = 200000   // URLs asked for
	waybackMaxBody = 64 << 20 // bytes read
)

// Wayback finds hostnames in the Wayback Machine's index of archived URLs
// (#193): one HTTPS request per domain, no API key. The zero value uses
// WaybackURL and http.DefaultClient.
type Wayback struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
	Timeout   time.Duration // per lookup; 0 means 60s
}

// Name is the source's -sources name.
func (Wayback) Name() string { return "wayback" }

// Names returns the hostnames under domain that appear in archived URLs,
// relative to it, sorted and deduplicated. The domain itself, other domains
// and invalid names are dropped.
func (w Wayback) Names(ctx context.Context, domain string) ([]string, error) {
	base := w.BaseURL
	if base == "" {
		base = WaybackURL
	}
	hc := w.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	q := url.Values{
		"url":       {domain},
		"matchType": {"domain"},
		"fl":        {"original"},
		"collapse":  {"urlkey"},
		"limit":     {strconv.Itoa(waybackLimit)},
	}
	resp, err := retryhttp.Get(ctx, hc, "wayback machine lookup", func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if w.UserAgent != "" {
			req.Header.Set("User-Agent", w.UserAgent)
		}
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	names, err := hostNames(io.LimitReader(resp.Body, waybackMaxBody), domain)
	if err != nil {
		return nil, fmt.Errorf("wayback machine lookup: reading %s's answer: %w", resp.Request.URL.Host, err)
	}
	return names, nil
}

// hostNames reads one archived URL per line and returns the hosts under
// domain, relative to it.
func hostNames(r io.Reader, domain string) ([]string, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	set := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.Contains(line, "://") {
			line = "http://" + line
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		rel, ok := strings.CutSuffix(host, "."+domain)
		if !ok || rel == "" {
			continue
		}
		if norm, ok := wordlist.Normalize(rel); ok {
			set[norm] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}
