package passive

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/retryhttp"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// Failing test servers are retried at once, not after a real backoff.
func init() {
	retryhttp.Sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
}

func TestParseList(t *testing.T) {
	got, err := ParseList(" Wayback, ct ,,ct")
	if err != nil || !slices.Equal(got, []string{"ct", "wayback"}) {
		t.Errorf("ParseList = %q, %v; want [ct wayback] in Known order", got, err)
	}
	if got, err := ParseList(""); err != nil || got != nil {
		t.Errorf("ParseList(\"\") = %q, %v; want none", got, err)
	}
	if _, err := ParseList("ct,shodan"); err == nil || !strings.Contains(err.Error(), "shodan") {
		t.Errorf("an unknown source was accepted: %v", err)
	}
}

func TestNewKnowsEverySource(t *testing.T) {
	for _, name := range Known {
		s, err := New(name, Options{})
		if err != nil || s.Name() != name {
			t.Errorf("New(%q) = %v, %v", name, s, err)
		}
		if Labels[name] == "" {
			t.Errorf("%q has no label", name)
		}
	}
}

// TestWayback covers #193: archived URLs give their hosts under the domain,
// relative, sorted and deduplicated.
func TestWayback(t *testing.T) {
	queries := make(chan string, 1) // the handler runs on the server's goroutine
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries <- r.URL.RawQuery
		_, _ = w.Write([]byte(strings.Join([]string{
			"http://www.example.com/",
			"https://Old-Shop.Example.com:8443/cart?x=1",
			"http://www.example.com:80/about",
			"dev.api.example.com/robots.txt",
			"http://example.com/",
			"http://example.com.evil.test/",
			"http://bad_name!.example.com/",
			"",
		}, "\n")))
	}))
	defer srv.Close()
	names, err := Wayback{BaseURL: srv.URL}.Names(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"dev.api", "old-shop", "www"}; !slices.Equal(names, want) {
		t.Errorf("Names = %q, want %q", names, want)
	}
	query := <-queries
	for _, p := range []string{"url=example.com", "matchType=domain", "fl=original", "collapse=urlkey"} {
		if !strings.Contains(query, p) {
			t.Errorf("query %q lacks %s", query, p)
		}
	}
}

// TestWaybackTruncated covers #272: an answer that fills the URL limit or
// the read limit returns its names with a Truncated error saying which.
func TestWaybackTruncated(t *testing.T) {
	body := "http://a.example.com/\nhttp://b.example.com/\nhttp://c.example.com/\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	savedLimit, savedBody := waybackLimit, waybackMaxBody
	t.Cleanup(func() { waybackLimit, waybackMaxBody = savedLimit, savedBody })

	waybackLimit = 3
	names, err := Wayback{BaseURL: srv.URL}.Names(context.Background(), "example.com")
	var tr *Truncated
	if !errors.As(err, &tr) || !strings.Contains(err.Error(), "limit of 3 URLs") || len(names) != 3 {
		t.Errorf("at the URL limit: names %q, err %v; want all 3 names and a Truncated error", names, err)
	}

	waybackLimit, waybackMaxBody = 1000, int64(len("http://a.example.com/\nhttp://b.ex"))
	names, err = Wayback{BaseURL: srv.URL}.Names(context.Background(), "example.com")
	if !errors.As(err, &tr) || !strings.Contains(err.Error(), "read limit") || !slices.Contains(names, "a") {
		t.Errorf("at the read limit: names %q, err %v; want a Truncated error and the names read", names, err)
	}

	waybackMaxBody = 1 << 20
	if names, err := (Wayback{BaseURL: srv.URL}).Names(context.Background(), "example.com"); err != nil || len(names) != 3 {
		t.Errorf("within the limits: names %q, err %v; want 3 and no error", names, err)
	}
}

// TestMerge covers #265: the merge shared by the CLI and pkg/subenum keeps
// the entries' order, appends new names after them in order, normalises,
// and drops duplicates, invalid names and names already present.
func TestMerge(t *testing.T) {
	entries := []string{"www", "mail"}
	have := map[string]bool{"www": true, "mail": true}
	got, added := Merge(entries, have, []string{"API", "www", "bad_name!", "dev.api", "api", strings.Repeat("a", 64)}, "example.com")
	if want := []string{"www", "mail", "api", "dev.api"}; !slices.Equal(got, want) || added != 2 {
		t.Errorf("Merge = %q, %d; want %q, 2", got, added, want)
	}
	if !have["api"] || !have["dev.api"] {
		t.Errorf("have = %v; want the new names recorded", have)
	}
	if got, added := Merge(got, have, []string{"api"}, "example.com"); len(got) != 4 || added != 0 {
		t.Errorf("a repeated merge added %d: %q", added, got)
	}
}

// TestCTTruncated covers #251: a crt.sh answer cut off at the read limit
// gives the names before the cut with a Truncated error.
func TestCTTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name_value": "a.example.com"},{"name_value": "`))
		chunk := strings.Repeat("x", 1<<20)
		for range 65 { // past crt.sh's 64 MiB read limit
			if _, err := w.Write([]byte(chunk)); err != nil {
				return // the client stopped reading
			}
		}
	}))
	defer srv.Close()
	src, err := New("ct", Options{BaseURLs: map[string]string{"ct": srv.URL + "/"}})
	if err != nil {
		t.Fatal(err)
	}
	names, err := src.Names(context.Background(), "example.com")
	var tr *Truncated
	if !errors.As(err, &tr) || tr.Source != "ct" || !strings.Contains(err.Error(), "read limit") || !slices.Equal(names, []string{"a"}) {
		t.Errorf("names %q, err %v; want [a] and a ct Truncated error naming the read limit", names, err)
	}
}

func TestWaybackError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := (Wayback{BaseURL: srv.URL}).Names(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("err = %v, want the 503", err)
	}
}

// TestWaybackEdgeCases covers #259: an over-long line is skipped rather than
// failing the answer, and odd hosts are handled.
func TestWaybackEdgeCases(t *testing.T) {
	body := strings.Join([]string{
		"http://" + strings.Repeat("a", 2<<20) + ".example.com/", // 2 MiB: skipped
		"http://www.example.com/",
		"http://user:pw@login.example.com/",      // userinfo
		"http://[2001:db8::1]/x",                 // IPv6 literal
		"http://*.wild.example.com/",             // wildcard: not a name
		"http://%zz.example.com/",                // malformed URL
		"https://Shop.EXAMPLE.com.:443/cart",     // case and trailing dot
		"http://evil.example.com.attacker.test/", // a lookalike outside the domain
		"no-newline.example.com",                 // last line without a newline
	}, "\n")
	names, lines, err := hostNames(strings.NewReader(body), "EXAMPLE.com.")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"login", "no-newline", "shop", "www"}; !slices.Equal(names, want) {
		t.Errorf("names = %q, want %q", names, want)
	}
	if lines != 9 {
		t.Errorf("lines = %d, want 9 (the skipped line counts toward the URL limit)", lines)
	}
}

// TestWaybackTransportError: a connection dropped mid-answer is reported,
// not taken for an empty index.
func TestWaybackTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte("http://www.example.com/\n"))
	}))
	defer srv.Close()
	if names, err := (Wayback{BaseURL: srv.URL}).Names(context.Background(), "example.com"); err == nil {
		t.Errorf("a short body was accepted: names %q", names)
	}
}

// FuzzHostNames: any answer parses without panicking, and every name it
// gives is a valid entry under the domain (#259).
func FuzzHostNames(f *testing.F) {
	f.Add("http://www.example.com/\nhttps://u@API.example.com:8443/x\n", "example.com")
	f.Add("[::1]\n*.example.com\n\n\r\n%zz", "Example.COM.")
	f.Fuzz(func(t *testing.T, body, domain string) {
		names, _, err := hostNames(strings.NewReader(body), domain)
		if err != nil {
			t.Fatalf("reading from memory failed: %v", err)
		}
		if !slices.IsSorted(names) {
			t.Errorf("names not sorted: %q", names)
		}
		for _, n := range names {
			if norm, ok := wordlist.Normalize(n); !ok || norm != n {
				t.Errorf("name %q is not a normalised entry", n)
			}
		}
	})
}
