// Package retry retries rate-limited or transiently failed HTTP requests with jittered backoff.
package retry

import (
	// Standard
	"context"
	"math/rand/v2"
	"net/http"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	// External
	"golang.org/x/time/rate"
)

const (
	baseDelay = 500 * time.Millisecond
	maxDelay  = 10 * time.Second
)

// Transport errors are not retried: timeouts would burn the caller's runtime budget.
var retryableStatusCodes = map[int]bool{
	http.StatusTooManyRequests:    true,
	http.StatusBadGateway:         true,
	http.StatusServiceUnavailable: true,
	http.StatusGatewayTimeout:     true,
}

// Overridden in tests.
var sendRequest = request.SendRequest

// Do calls attempt, retrying retryable status codes up to maxRetries times with decorrelated-jitter
// backoff, spreading rate-limited requests over time instead of dropping them. Each attempt waits on
// limiter when set. Returns the retry count.
func Do(ctx context.Context, limiter *rate.Limiter, maxRetries int, attempt func() (int, error)) (int, error) {
	delay := baseDelay
	for retries := 0; ; retries++ {
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return retries, err
			}
		}
		status, err := attempt()
		if err != nil || retries >= maxRetries || !retryableStatusCodes[status] {
			return retries, err
		}
		delay = nextDelay(delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return retries, ctx.Err()
		}
	}
}

// SendRequest is request.SendRequest with Do's retries. Returns the last response and the retry count.
func SendRequest(ctx context.Context, config common.SendHttpRequestConfig, limiter *rate.Limiter, maxRetries int) (*common.HttpRequestResponse, int, error) {
	var resp *common.HttpRequestResponse
	retries, err := Do(ctx, limiter, maxRetries, func() (int, error) {
		var err error
		resp, err = sendRequest(ctx, config)
		if err != nil || resp.Response == nil || resp.Response.StatusCode == nil {
			return 0, err
		}
		return *resp.Response.StatusCode, nil
	})
	if err != nil {
		return nil, retries, err
	}
	return resp, retries, nil
}

// nextDelay is uniform in [base, 3*prev), capped at max.
func nextDelay(prev time.Duration) time.Duration {
	upper := max(prev*3, baseDelay+1)
	return min(maxDelay, baseDelay+rand.N(upper-baseDelay))
}
