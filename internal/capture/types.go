package capture

import (
	"context"
)

type CaptureOptions struct{}
type CaptureResult struct {
	Content    []byte   `json:"content,omitempty" yaml:"content,omitempty"`
	StatusCode *int     `json:"statusCode,omitempty" yaml:"statusCode,omitempty"`
	URL        string   `json:"url,omitempty" yaml:"url,omitempty"`
	Errors     []string `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type WebPageCapturer interface {
	Capture(ctx context.Context, url string, options *CaptureOptions) (*CaptureResult, error)
	Close() error
}

func NewCaptureResult(URL string) *CaptureResult {
	return &CaptureResult{
		StatusCode: nil,
		URL:        URL,
		Errors:     []string{},
	}
}
