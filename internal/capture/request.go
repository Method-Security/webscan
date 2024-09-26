package capture

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
)

type RequestWebpageCapturer struct {
	Client http.Client
}

func NewRequestWebpageCapturer() *RequestWebpageCapturer {
	return &RequestWebpageCapturer{
		Client: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (r *RequestWebpageCapturer) Capture(ctx context.Context, url string, options *Options) (*Result, error) {
	result := NewCaptureResult(url)
	resp, err := r.Client.Get(url)

	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = cerr
		}
	}()

	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}
	result.StatusCode = &resp.StatusCode

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	} else {
		result.Content = body
	}

	return result, nil
}

func (r *RequestWebpageCapturer) Close() error {
	return nil
}
