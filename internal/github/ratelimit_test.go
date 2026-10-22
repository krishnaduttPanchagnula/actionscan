package github

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	gh "github.com/google/go-github/v62/github"
)

// A rate-limited call must be retried, not surfaced as a failed scan.
func TestWithRetry_RetriesRateLimit(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), func() error {
		calls++
		if calls < 3 {
			return &gh.RateLimitError{
				Message:  "API rate limit exceeded",
				Response: &http.Response{StatusCode: 403},
				Rate:     gh.Rate{Reset: gh.Timestamp{Time: time.Now().Add(-time.Second)}},
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withRetry must recover from a rate limit: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

// A secondary rate limit carries a Retry-After hint.
func TestWithRetry_RetriesAbuseLimit(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), func() error {
		calls++
		if calls < 2 {
			d := 1 * time.Millisecond
			return &gh.AbuseRateLimitError{
				Message:    "secondary rate limit",
				Response:   &http.Response{StatusCode: 403},
				RetryAfter: &d,
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withRetry must recover from an abuse limit: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2", calls)
	}
}

// GitHub answers secondary rate limits with 429, which go-github
// reports as a plain error response — not as a rate-limit type.
// Treating it as fatal would abort a whole org scan over a pause.
func TestWithRetry_RetriesTooManyRequests(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), func() error {
		calls++
		if calls < 3 {
			return &gh.ErrorResponse{
				Response: &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{"Retry-After": []string{"1"}},
				},
				Message: "secondary rate limit",
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withRetry must recover from a 429: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

// A real error must pass straight through — it is not a rate limit.
func TestWithRetry_PassesThroughRealErrors(t *testing.T) {
	sentinel := errors.New("boom")
	calls := 0
	err := withRetry(context.Background(), func() error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the original error", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no retry for a non-rate-limit error)", calls)
	}
}

// A permanently rate-limited call must eventually give up rather than
// retry forever.
func TestWithRetry_GivesUpEventually(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), func() error {
		calls++
		return &gh.RateLimitError{
			Message:  "API rate limit exceeded",
			Response: &http.Response{StatusCode: 403},
			Rate:     gh.Rate{Reset: gh.Timestamp{Time: time.Now().Add(-time.Second)}},
		}
	})
	if err == nil {
		t.Fatal("a permanently rate-limited call must return an error")
	}
	if calls != maxRetries+1 {
		t.Errorf("calls = %d, want %d", calls, maxRetries+1)
	}
}
