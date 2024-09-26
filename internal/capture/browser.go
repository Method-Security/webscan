package capture

import (
	"context"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
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
		Browser:        rod.New().Client(client).MustConnect(),
		TimeoutSeconds: timeout,
	}
}

func (b *BrowserWebpageCapturer) Capture(ctx context.Context, url string, options *Options) (*Result, error) {
	result := NewCaptureResult(url)
	log := svc1log.FromContext(ctx)

	if b.Browser == nil {
		log.Debug("Initializing browser")
		b.InitializeBrowser()
	}

	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	var page *rod.Page
	err := rod.Try(func() {
		page = b.Browser.MustPage(url).Context(pageCtx)
	})
	if err != nil {
		log.Error("Failed to create page", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}
	log.Debug("Successfully connected to page")

	page = page.MustWaitStable()
	evalResult, err := page.Eval(`() => document.documentElement.outerHTML`)
	if err != nil {
		log.Error("Failed to evaluate page content", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
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

func (b *BrowserWebpageCapturer) Close(ctx context.Context) error {
	svc1log.FromContext(ctx).Debug("Closing browser")
	if b.Browser != nil {
		err := b.Browser.Close()
		if err != nil {
			svc1log.FromContext(ctx).Error("Failed to close browser", svc1log.SafeParam("error", err))
			return err
		}
	}
	return nil
}
