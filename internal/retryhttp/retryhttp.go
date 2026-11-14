// Package retryhttp sends the passive sources' HTTP requests, retrying the
// failures a busy public service gives back (#271): 429, 502, 503 and 504,
// and transport errors such as a reset connection. crt.sh in particular
// often answers 502 or 503 under load, and one failed request used to cost a
// scan all of that source's names.
package retryhttp

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Retries is how many times a failed request is sent again.
const Retries = 2

// maxWait caps one wait, Retry-After included, so a long Retry-After does
// not stall a scan.
const maxWait = 30 * time.Second

// backoff is the wait before each retry when the server names none.
var backoff = []time.Duration{2 * time.Second, 5 * time.Second}

// Sleep waits for d or until ctx ends. Tests of code that reaches a failing
// test server replace it so retries do not wait for real.
var Sleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// retryable reports whether a response status is worth another try.
func retryable(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// Get sends a GET request built by newReq through hc, up to Retries more
// times while it fails in a retryable way and ctx lasts. It returns the
// first 200 response, whose body the caller closes, or the last failure as
// an error naming the host and status. what prefixes errors, such as
// "wayback machine lookup".
func Get(ctx context.Context, hc *http.Client, what string, newReq func(context.Context) (*http.Request, error)) (*http.Response, error) {
	var last error
	for attempt := 0; ; attempt++ {
		req, err := newReq(ctx)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		var wait time.Duration
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, fmt.Errorf("%s: %w", what, err)
			}
			last = fmt.Errorf("%s: %w", what, err)
		case resp.StatusCode == http.StatusOK:
			return resp, nil
		default:
			last = fmt.Errorf("%s: %s returned %s", what, req.URL.Host, resp.Status)
			_ = resp.Body.Close()
			if !retryable(resp.StatusCode) {
				return nil, last
			}
			wait = retryAfter(resp.Header.Get("Retry-After"), time.Now())
		}
		if attempt == Retries {
			return nil, last
		}
		if wait <= 0 {
			wait = backoff[min(attempt, len(backoff)-1)]
		}
		wait = min(wait, maxWait)
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < wait {
			return nil, last // the lookup's time runs out before the retry could go
		}
		if Sleep(ctx, wait) != nil {
			return nil, last
		}
	}
}

// retryAfter reads a Retry-After header, in seconds or as an HTTP date; zero
// when absent or unreadable.
func retryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return t.Sub(now)
	}
	return 0
}
