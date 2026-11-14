package retryhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// server answers each request with the next status in codes (the last one
// repeats), counting the requests, and records the waits Get asks for.
func server(t *testing.T, header http.Header, codes ...int) (url string, hits *atomic.Int32, waits *[]time.Duration) {
	t.Helper()
	hits = new(atomic.Int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(hits.Add(1)) - 1
		for k, v := range header {
			w.Header()[k] = v
		}
		w.WriteHeader(codes[min(n, len(codes)-1)])
	}))
	t.Cleanup(srv.Close)
	waits = new([]time.Duration)
	saved := Sleep
	t.Cleanup(func() { Sleep = saved })
	Sleep = func(_ context.Context, d time.Duration) error {
		*waits = append(*waits, d)
		return nil
	}
	return srv.URL, hits, waits
}

func get(ctx context.Context, url string) (*http.Response, error) {
	return Get(ctx, http.DefaultClient, "test lookup", func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	})
}

func TestGetRetriesBusyAnswers(t *testing.T) {
	url, hits, waits := server(t, nil, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusOK)
	resp, err := get(context.Background(), url)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if hits.Load() != 3 || len(*waits) != 2 || (*waits)[0] != backoff[0] || (*waits)[1] != backoff[1] {
		t.Errorf("%d requests, waits %v; want 3 requests with waits %v", hits.Load(), *waits, backoff)
	}
}

func TestGetGivesUpAfterRetries(t *testing.T) {
	url, hits, _ := server(t, nil, http.StatusTooManyRequests)
	if _, err := get(context.Background(), url); err == nil || !strings.Contains(err.Error(), "429") || !strings.HasPrefix(err.Error(), "test lookup: ") {
		t.Errorf("err = %v, want the last 429 named", err)
	}
	if hits.Load() != Retries+1 {
		t.Errorf("%d requests, want %d", hits.Load(), Retries+1)
	}
}

func TestGetDoesNotRetryOtherStatuses(t *testing.T) {
	url, hits, _ := server(t, nil, http.StatusNotFound, http.StatusOK)
	if _, err := get(context.Background(), url); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want the 404", err)
	}
	if hits.Load() != 1 {
		t.Errorf("a 404 was retried: %d requests", hits.Load())
	}
}

func TestGetHonoursRetryAfter(t *testing.T) {
	url, _, waits := server(t, http.Header{"Retry-After": {"7"}}, http.StatusTooManyRequests, http.StatusOK)
	resp, err := get(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(*waits) != 1 || (*waits)[0] != 7*time.Second {
		t.Errorf("waits = %v, want [7s]", *waits)
	}

	url, hits, waits := server(t, http.Header{"Retry-After": {"3600"}}, http.StatusTooManyRequests, http.StatusOK)
	resp, err = get(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if hits.Load() != 2 || (*waits)[0] != maxWait {
		t.Errorf("a long Retry-After: waits %v, want capped at %v", *waits, maxWait)
	}
}

func TestGetStopsAtTheDeadline(t *testing.T) {
	url, hits, _ := server(t, nil, http.StatusServiceUnavailable, http.StatusOK)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second) // shorter than the first backoff
	defer cancel()
	if _, err := get(ctx, url); err == nil {
		t.Error("Get retried past its deadline")
	}
	if hits.Load() != 1 {
		t.Errorf("%d requests, want 1: the retry could not finish in time", hits.Load())
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	for v, want := range map[string]time.Duration{
		"":                              0,
		"12":                            12 * time.Second,
		"-3":                            0,
		"soon":                          0,
		"Fri, 13 Nov 2026 12:00:10 GMT": 10 * time.Second,
	} {
		if got := retryAfter(v, now); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", v, got, want)
		}
	}
}
