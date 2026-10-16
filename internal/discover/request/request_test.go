package discoverrequest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"
)

func TestPerformRequestPreservesEncodedPathOnWire(t *testing.T) {
	path := "/ftp/package.json.bak%2500.md"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.RequestURI != path {
			t.Errorf("server received RequestURI %q, want %q", request.RequestURI, path)
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	report := PerformRequest(context.Background(), discover.DiscoverRequestConfig{
		Target:          server.URL + path,
		HttpMethod:      common.HttpMethodGet,
		MaxRedirects:    0,
		FollowRedirects: false,
		VerifyTls:       true,
		Timeout:         5,
		UserAgent:       common.UserAgentPresetCurl,
	})
	if len(report.Errors) > 0 {
		t.Fatalf("PerformRequest() returned errors: %v", report.Errors)
	}
}

func TestPerformRequestRetriesRateLimitWithFullBody(t *testing.T) {
	const body = `{"key":"value"}`
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if got, _ := io.ReadAll(request.Body); string(got) != body {
			t.Errorf("attempt %d: body %q, want %q", calls, got, body)
		}
		if calls == 1 {
			writer.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	jsonBody := body
	report := PerformRequest(context.Background(), discover.DiscoverRequestConfig{
		Target:     server.URL,
		HttpMethod: common.HttpMethodPost,
		JsonBody:   &jsonBody,
		Timeout:    5,
		Retries:    5,
		UserAgent:  common.UserAgentPresetCurl,
	})
	if len(report.Errors) > 0 || calls != 2 || *report.Result.Request.Response.StatusCode != http.StatusOK {
		t.Fatalf("got calls=%d status=%v errors=%v", calls, report.Result.Request.Response.StatusCode, report.Errors)
	}
}
