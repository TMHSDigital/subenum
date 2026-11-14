package ct

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TMHSDigital/subenum/internal/retryhttp"
)

// Failing test servers are retried at once, not after a real backoff.
func init() {
	retryhttp.Sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
}

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

// names runs one lookup for example.com against srv.
func names(ctx context.Context, srv *httptest.Server, timeout time.Duration) ([]string, error) {
	return Client{BaseURL: srv.URL + "/", Timeout: timeout}.Names(ctx, "example.com")
}

func TestNamesNormalises(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"name_value": "a.example.com\n*.example.com\nB.EXAMPLE.COM\nother.org"},
			{"name_value": "b.example.com\nA.example.com"}
		]`))
	}))
	defer srv.Close()

	got, err := names(context.Background(), srv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a", "b"}; !slices.Equal(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
}

func TestNamesTransportError(t *testing.T) {
	// The server accepts the connection and drops it without answering.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer srv.Close()

	_, err := names(context.Background(), srv, 0)
	if err == nil {
		t.Fatal("a dropped connection was not reported")
	}
	if !strings.Contains(err.Error(), "certificate transparency lookup") {
		t.Errorf("error %q lacks the lookup context", err)
	}
}

func TestNamesMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"broken"`))
	}))
	defer srv.Close()

	_, err := names(context.Background(), srv, 0)
	if err == nil {
		t.Fatal("malformed JSON was not reported")
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	if msg := err.Error(); !strings.Contains(msg, "reading "+host+"'s answer") {
		t.Errorf("error %q lacks the reading-answer context for %s", msg, host)
	}
}

func TestNamesOversizedBody(t *testing.T) {
	// A valid JSON array longer than maxBody: the cut-off must surface as an
	// error, not as a silently truncated name list.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[{"name_value": "a.example.com"},{"name_value": "`)
		chunk := strings.Repeat("x", 1<<20)
		for written := 0; written <= maxBody; written += len(chunk) {
			if _, err := io.WriteString(w, chunk); err != nil {
				return // the client stopped reading
			}
		}
		_, _ = io.WriteString(w, `.example.com"}]`)
	}))
	defer srv.Close()

	got, err := names(context.Background(), srv, 0)
	if err == nil {
		t.Fatalf("an oversized answer was accepted: %d names", len(got))
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("error = %v, want one wrapping io.ErrUnexpectedEOF", err)
	}
}

func TestNamesTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	_, err := names(context.Background(), srv, 50*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want context.DeadlineExceeded", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("lookup took %v past a 50ms timeout", took)
	}
}

func TestNamesCancelled(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := names(ctx, srv, 0)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("a cancelled lookup still reached the server %d times", n)
	}
}

func TestNamesRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := names(context.Background(), srv, 0)
	if err == nil {
		t.Fatal("a 429 was not reported")
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	msg := err.Error()
	if !strings.Contains(msg, "429 Too Many Requests") || !strings.Contains(msg, host) {
		t.Errorf("error %q does not report the rate limit from %s", msg, host)
	}
}
