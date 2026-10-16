package discoverdirectory

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
	retryBaseDelay = 500 * time.Millisecond
	retryMaxDelay  = 10 * time.Second
)

// Transport errors are not retried: timeouts would burn the max-runtime budget.
var retryableStatusCodes = map[int]bool{
	http.StatusTooManyRequests:    true,
	http.StatusBadGateway:         true,
	http.StatusServiceUnavailable: true,
	http.StatusGatewayTimeout:     true,
}

// Overridden in tests.
var sendRequest = request.SendRequest

// sendWithBackoff retries retryable statuses with jittered backoff, spreading rate-limited paths
// over time instead of dropping them. Returns the last response and the retry count.
func sendWithBackoff(ctx context.Context, config common.SendHttpRequestConfig, limiter *rate.Limiter, maxRetries int) (*common.HttpRequestResponse, int, error) {
	delay := retryBaseDelay
	for attempt := 0; ; attempt++ {
		if err := waitForDirectoryRateLimit(ctx, limiter); err != nil {
			return nil, attempt, err
		}
		resp, err := sendRequest(ctx, config)
		if err != nil || attempt >= maxRetries || !isRetryable(resp) {
			return resp, attempt, err
		}
		delay = nextBackoffDelay(delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return resp, attempt, nil
		}
	}
}

func isRetryable(resp *common.HttpRequestResponse) bool {
	if resp == nil || resp.Response == nil || resp.Response.StatusCode == nil {
		return false
	}
	return retryableStatusCodes[*resp.Response.StatusCode]
}

// nextBackoffDelay is uniform in [base, 3*prev), capped at max.
func nextBackoffDelay(prev time.Duration) time.Duration {
	upper := max(prev*3, retryBaseDelay+1)
	return min(retryMaxDelay, retryBaseDelay+rand.N(upper-retryBaseDelay))
}
