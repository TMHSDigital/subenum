package passive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

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

func TestWaybackError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := (Wayback{BaseURL: srv.URL}).Names(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("err = %v, want the 503", err)
	}
}
