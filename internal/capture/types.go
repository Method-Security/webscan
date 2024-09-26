package capture

import (
	"context"
)

type Options struct{}
type Result struct {
	Content    []byte   `json:"content,omitempty" yaml:"content,omitempty"`
	StatusCode *int     `json:"statusCode,omitempty" yaml:"statusCode,omitempty"`
	URL        string   `json:"url,omitempty" yaml:"url,omitempty"`
	Errors     []string `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type WebPageCapturer interface {
	Capture(ctx context.Context, url string, options *Options) (*Result, error)
	Close() error
}

func NewCaptureResult(URL string) *Result {
	return &Result{
		StatusCode: nil,
		URL:        URL,
		Errors:     []string{},
	}
}
