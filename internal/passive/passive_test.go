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

func TestWaybackError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := (Wayback{BaseURL: srv.URL}).Names(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("err = %v, want the 503", err)
	}
}
