package ct

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestNames(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query().Get("q")
		_, _ = w.Write([]byte(`[
			{"name_value": "www.example.com\nAPI.example.com"},
			{"name_value": "*.dev.example.com"},
			{"name_value": "example.com\nother.org\nexample.com.evil.net"},
			{"name_value": "bad_label!.example.com\napi.example.com."}
		]`))
	}))
	defer srv.Close()

	got, err := Client{BaseURL: srv.URL + "/"}.Names(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"api", "dev", "www"}; !slices.Equal(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
	if query != "%.example.com" {
		t.Errorf("query q = %q, want %%.example.com", query)
	}
}

func TestNamesReportsFailures(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer down.Close()
	if _, err := (Client{BaseURL: down.URL + "/"}).Names(context.Background(), "example.com"); err == nil {
		t.Error("a 502 was not reported")
	}
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>rate limited</html>"))
	}))
	defer garbage.Close()
	if _, err := (Client{BaseURL: garbage.URL + "/"}).Names(context.Background(), "example.com"); err == nil {
		t.Error("a non-JSON answer was not reported")
	}
}
