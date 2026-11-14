package passive

import (
	"bufio"
	"context"
	"errors"
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
// the index returns them one per line. Variables so tests can lower them.
var (
	waybackLimit         = 200000   // URLs asked for
	waybackMaxBody int64 = 64 << 20 // bytes read
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
	body := &io.LimitedReader{R: resp.Body, N: waybackMaxBody}
	names, lines, err := hostNames(body, domain)
	if err != nil {
		return nil, fmt.Errorf("wayback machine lookup: reading %s's answer: %w", resp.Request.URL.Host, err)
	}
	switch {
	case lines >= waybackLimit:
		return names, &Truncated{Source: "wayback", Why: fmt.Sprintf("the index returned its limit of %d URLs", waybackLimit)}
	case body.N <= 0:
		return names, &Truncated{Source: "wayback", Why: fmt.Sprintf("the answer reached the %d MiB read limit", waybackMaxBody>>20)}
	}
	return names, nil
}

// waybackMaxLine bounds one archived URL. A longer line is skipped, not
// fatal: it used to fail the whole answer and lose every name (#259).
const waybackMaxLine = 1 << 20

// hostNames reads one archived URL per line and returns the hosts under
// domain, relative to it, and how many lines it read.
func hostNames(r io.Reader, domain string) ([]string, int, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	set := map[string]bool{}
	br := bufio.NewReaderSize(r, 64<<10)
	lines := 0
	for {
		raw, tooLong, err := readURLLine(br)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, lines, err
		}
		line := strings.TrimSpace(string(raw))
		if tooLong {
			lines++
		} else if line != "" {
			lines++
			addHost(set, line, domain)
		}
		if err != nil { // io.EOF, after the last line
			break
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, lines, nil
}

// readURLLine reads one line, without its newline. A line over
// waybackMaxLine is read to its end and returned empty with tooLong set. The
// last line may lack a newline: it comes with io.EOF.
func readURLLine(br *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > waybackMaxLine+1 { // +1: the newline
				line, tooLong = nil, true
			} else {
				line = append(line, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, tooLong, err
	}
}

// addHost adds the host of one archived URL to set, relative to domain, if
// it is a valid name under it.
func addHost(set map[string]bool, line, domain string) {
	if !strings.Contains(line, "://") {
		line = "http://" + line
	}
	u, err := url.Parse(line)
	if err != nil {
		return
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	rel, ok := strings.CutSuffix(host, "."+domain)
	if !ok || rel == "" {
		return
	}
	if norm, ok := wordlist.Normalize(rel); ok {
		set[norm] = true
	}
}
