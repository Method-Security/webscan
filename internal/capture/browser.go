package capture

import (
	"context"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/launcher"
)

type BrowserWebpageCapturer struct {
	PathToBrowser  *string
	Browser        *rod.Browser
	TimeoutSeconds int
}

func NewBrowserWebpageCapturer(pathToBrowser *string, timeout int) *BrowserWebpageCapturer {
	return &BrowserWebpageCapturer{
		PathToBrowser:  pathToBrowser,
		Browser:        nil,
		TimeoutSeconds: timeout,
	}
}

func NewBrowserWebpageCapturerWithClient(client *cdp.Client, timeout int) *BrowserWebpageCapturer {
	return &BrowserWebpageCapturer{
		PathToBrowser:  nil,
		Browser:        rod.New().Client(client),
		TimeoutSeconds: timeout,
	}
}

func (b *BrowserWebpageCapturer) Capture(ctx context.Context, url string, options *CaptureOptions) (*CaptureResult, error) {
	result := NewCaptureResult(url)

	if b.Browser == nil {
		b.InitializeBrowser()
	}

	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	var page *rod.Page
	err := rod.Try(func() {
		page = b.Browser.MustPage(url).Context(pageCtx)
	})
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}

	page = page.MustWaitStable()
	evalResult, err := page.Eval(`() => document.documentElement.outerHTML`)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}

	result.Content = []byte(evalResult.Value.String())
	return result, nil
}

func (b *BrowserWebpageCapturer) InitializeBrowser() {
	var browserURL string
	if b.PathToBrowser != nil && *b.PathToBrowser != "" {
		browserURL = launcher.New().Headless(true).Bin(*b.PathToBrowser).MustLaunch()
	} else {
		browserURL = launcher.New().Headless(true).MustLaunch()
	}

	b.Browser = rod.New().ControlURL(browserURL).MustConnect()
}

func (b *BrowserWebpageCapturer) Close() error {
	if b.Browser != nil {
		return b.Browser.Close()
	}
	return nil
}
