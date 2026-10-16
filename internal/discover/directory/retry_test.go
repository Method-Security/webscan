package discoverdirectory

import (
	"context"
	"errors"
	"testing"
	"time"

	common "github.com/Method-Security/webscan/generated/go/common"
)

func responseWithStatus(status int) *common.HttpRequestResponse {
	return &common.HttpRequestResponse{Response: &common.HttpResponse{StatusCode: &status}}
}

// stubSend replays statuses in order (repeating the last) and counts calls.
func stubSend(t *testing.T, err error, statuses ...int) *int {
	t.Helper()
	calls := 0
	orig := sendRequest
	sendRequest = func(context.Context, common.SendHttpRequestConfig) (*common.HttpRequestResponse, error) {
		status := statuses[min(calls, len(statuses)-1)]
		calls++
		if err != nil {
			return nil, err
		}
		return responseWithStatus(status), nil
	}
	t.Cleanup(func() { sendRequest = orig })
	return &calls
}

func TestSendWithBackoffRetriesUntilSuccess(t *testing.T) {
	calls := stubSend(t, nil, 429, 503, 200)
	resp, retries, err := sendWithBackoff(context.Background(), common.SendHttpRequestConfig{}, nil, 5)
	if err != nil || *resp.Response.StatusCode != 200 || retries != 2 || *calls != 3 {
		t.Fatalf("got status=%d retries=%d calls=%d err=%v", *resp.Response.StatusCode, retries, *calls, err)
	}
}

func TestSendWithBackoffStopsAtMaxRetries(t *testing.T) {
	calls := stubSend(t, nil, 429)
	resp, retries, _ := sendWithBackoff(context.Background(), common.SendHttpRequestConfig{}, nil, 1)
	if *resp.Response.StatusCode != 429 || retries != 1 || *calls != 2 {
		t.Fatalf("got status=%d retries=%d calls=%d", *resp.Response.StatusCode, retries, *calls)
	}
}

func TestSendWithBackoffNoRetriesWhenZero(t *testing.T) {
	calls := stubSend(t, nil, 429)
	if _, retries, _ := sendWithBackoff(context.Background(), common.SendHttpRequestConfig{}, nil, 0); retries != 0 || *calls != 1 {
		t.Fatalf("got retries=%d calls=%d", retries, *calls)
	}
}

func TestSendWithBackoffDoesNotRetryOtherStatuses(t *testing.T) {
	calls := stubSend(t, nil, 404)
	if _, retries, _ := sendWithBackoff(context.Background(), common.SendHttpRequestConfig{}, nil, 5); retries != 0 || *calls != 1 {
		t.Fatalf("got retries=%d calls=%d", retries, *calls)
	}
}

func TestSendWithBackoffDoesNotRetryTransportErrors(t *testing.T) {
	calls := stubSend(t, errors.New("connection reset"), 0)
	if _, _, err := sendWithBackoff(context.Background(), common.SendHttpRequestConfig{}, nil, 5); err == nil || *calls != 1 {
		t.Fatalf("got calls=%d err=%v", *calls, err)
	}
}

func TestSendWithBackoffStopsOnContextCancel(t *testing.T) {
	calls := stubSend(t, nil, 429)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, _ = sendWithBackoff(ctx, common.SendHttpRequestConfig{}, nil, 5)
	if *calls != 1 || time.Since(start) >= retryBaseDelay {
		t.Fatalf("got calls=%d elapsed=%s", *calls, time.Since(start))
	}
}

func TestNextBackoffDelayBounds(t *testing.T) {
	prev := retryBaseDelay
	for range 1000 {
		d := nextBackoffDelay(prev)
		if d < retryBaseDelay || d > retryMaxDelay || d >= max(prev*3, retryBaseDelay+1) {
			t.Fatalf("prev %s: delay %s out of bounds", prev, d)
		}
		prev = d
	}
}
