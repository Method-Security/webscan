package retry

import (
	"context"
	"errors"
	"testing"
	"time"

	common "github.com/Method-Security/webscan/generated/go/common"
	"golang.org/x/time/rate"
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

func TestSendRequestRetriesUntilSuccess(t *testing.T) {
	calls := stubSend(t, nil, 429, 503, 200)
	resp, retries, err := SendRequest(context.Background(), common.SendHttpRequestConfig{}, nil, 5)
	if err != nil || *resp.Response.StatusCode != 200 || retries != 2 || *calls != 3 {
		t.Fatalf("got status=%d retries=%d calls=%d err=%v", *resp.Response.StatusCode, retries, *calls, err)
	}
}

func TestSendRequestStopsAtMaxRetries(t *testing.T) {
	calls := stubSend(t, nil, 429)
	resp, retries, _ := SendRequest(context.Background(), common.SendHttpRequestConfig{}, nil, 1)
	if *resp.Response.StatusCode != 429 || retries != 1 || *calls != 2 {
		t.Fatalf("got status=%d retries=%d calls=%d", *resp.Response.StatusCode, retries, *calls)
	}
}

func TestSendRequestNoRetriesWhenZero(t *testing.T) {
	calls := stubSend(t, nil, 429)
	if _, retries, _ := SendRequest(context.Background(), common.SendHttpRequestConfig{}, nil, 0); retries != 0 || *calls != 1 {
		t.Fatalf("got retries=%d calls=%d", retries, *calls)
	}
}

func TestSendRequestDoesNotRetryOtherStatuses(t *testing.T) {
	calls := stubSend(t, nil, 404)
	if _, retries, _ := SendRequest(context.Background(), common.SendHttpRequestConfig{}, nil, 5); retries != 0 || *calls != 1 {
		t.Fatalf("got retries=%d calls=%d", retries, *calls)
	}
}

func TestSendRequestDoesNotRetryTransportErrors(t *testing.T) {
	calls := stubSend(t, errors.New("connection reset"), 0)
	if _, _, err := SendRequest(context.Background(), common.SendHttpRequestConfig{}, nil, 5); err == nil || *calls != 1 {
		t.Fatalf("got calls=%d err=%v", *calls, err)
	}
}

func TestSendRequestStopsOnContextCancel(t *testing.T) {
	calls := stubSend(t, nil, 429)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	resp, _, err := SendRequest(ctx, common.SendHttpRequestConfig{}, nil, 5)
	if resp != nil || !errors.Is(err, context.DeadlineExceeded) || *calls != 1 || time.Since(start) >= baseDelay {
		t.Fatalf("got resp=%v err=%v calls=%d elapsed=%s", resp, err, *calls, time.Since(start))
	}
}

func TestDoWaitsOnLimiter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, err := Do(ctx, rate.NewLimiter(1, 1), 5, func() (int, error) { calls++; return 200, nil })
	if err == nil || calls != 0 {
		t.Fatalf("got calls=%d err=%v", calls, err)
	}
}

func TestNextDelayBounds(t *testing.T) {
	prev := baseDelay
	for range 1000 {
		d := nextDelay(prev)
		if d < baseDelay || d > maxDelay || d >= max(prev*3, baseDelay+1) {
			t.Fatalf("prev %s: delay %s out of bounds", prev, d)
		}
		prev = d
	}
}
