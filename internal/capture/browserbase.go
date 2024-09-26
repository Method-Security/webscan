package capture

import (
	"context"

	"github.com/go-rod/rod/lib/cdp"
)

type BrowserbaseWebpageCapturer struct {
	Capturer *BrowserWebpageCapturer
}

func NewBrowserbaseWebpageCapturer(ctx context.Context, sessionURL string, timeout int) *BrowserbaseWebpageCapturer {
	websocket := NewWebSocket(ctx, sessionURL)
	client := cdp.New().Start(websocket)
	return &BrowserbaseWebpageCapturer{
		Capturer: NewBrowserWebpageCapturerWithClient(client, timeout),
	}
}

func (b *BrowserbaseWebpageCapturer) Capture(ctx context.Context, url string, options *CaptureOptions) (*CaptureResult, error) {
	return b.Capturer.Capture(ctx, url, options)
}

func (b *BrowserbaseWebpageCapturer) Close() error {
	return b.Capturer.Close()
}
