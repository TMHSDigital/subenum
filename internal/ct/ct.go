// Package ct looks up subdomain names in Certificate Transparency logs
// through crt.sh (#130). Certificates name the hosts they cover, so CT shows
// real naming conventions (and forgotten hosts) without an API key. The
// names are only candidates: a scan still has to resolve them.
package ct

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/TMHSDigital/subenum/internal/retryhttp"
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

// Name is the source's -sources name.
func (Client) Name() string { return "ct" }

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
	resp, err := retryhttp.Get(ctx, hc, "certificate transparency lookup", func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if c.UserAgent != "" {
			req.Header.Set("User-Agent", c.UserAgent)
		}
		req.Header.Set("Accept", "application/json")
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body := &limitReader{r: resp.Body, n: maxBody}
	set := map[string]bool{}
	if err := decodeEntries(json.NewDecoder(body), set, domain); err != nil {
		if body.hit {
			// The array is cut off at the limit: keep the entries before the
			// cut instead of losing them all (#251).
			return sortedNames(set), fmt.Errorf("%w: the answer reached the %d MiB read limit", ErrTruncated, maxBody>>20)
		}
		return nil, fmt.Errorf("certificate transparency lookup: reading %s's answer: %w", resp.Request.URL.Host, err)
	}
	return sortedNames(set), nil
}

// ErrTruncated is returned, wrapped, with the names read before the answer
// reached its read limit: they are good, but some hosts may be missing.
var ErrTruncated = errors.New("certificate transparency answer truncated")

// decodeEntries streams crt.sh's JSON array one entry at a time, adding each
// entry's names to set, so memory follows the names, not the body (#251).
func decodeEntries(dec *json.Decoder, set map[string]bool, domain string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("want a JSON array, got %v", tok)
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for dec.More() {
		var e entry
		if err := dec.Decode(&e); err != nil {
			return err
		}
		addNames(set, e, domain)
	}
	_, err = dec.Token() // the closing ']'
	return err
}

// limitReader is io.LimitReader that records whether the limit cut the
// body short.
type limitReader struct {
	r   io.Reader
	n   int64
	hit bool
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		l.hit = true
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// addNames adds e's names that fall under domain to set, relative to it.
// Wildcard entries give their parent ("*.dev" gives "dev").
func addNames(set map[string]bool, e entry, domain string) {
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

func sortedNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
