package capture

import (
	"context"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type BrowserPageCapturer struct {
	PathToBrowser              *string
	Browser                    *rod.Browser
	TimeoutSeconds             int
	MinDOMStabalizeTimeSeconds int
}

func NewBrowserPageCapturer(pathToBrowser *string, timeout int, minDOMStabalizeTime int) *BrowserPageCapturer {
	return &BrowserPageCapturer{
		PathToBrowser:              pathToBrowser,
		Browser:                    nil,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: minDOMStabalizeTime,
	}
}

func NewBrowserPageCapturerWithClient(client *cdp.Client, timeout int, minDOMStabalizeTime int) *BrowserPageCapturer {
	return &BrowserPageCapturer{
		PathToBrowser:              nil,
		Browser:                    rod.New().Client(client).MustConnect(),
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: minDOMStabalizeTime,
	}
}

func (b *BrowserPageCapturer) Capture(ctx context.Context, url string, options *Options) (*Result, error) {
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

	// Navigate to the page
	err = page.Navigate(url)
	if err != nil {
		log.Error("Failed to navigate to page", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}

	// Wait for the page to load
	page.MustWaitLoad()

	evalResult, err := page.HTML()
	if err != nil {
		log.Error("Failed to evaluate page content", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}

	result.Content = []byte(evalResult)
	return result, nil
}

func (b *BrowserPageCapturer) InitializeBrowser() {
	var browserURL string
	if b.PathToBrowser != nil && *b.PathToBrowser != "" {
		browserURL = launcher.New().Headless(true).Bin(*b.PathToBrowser).MustLaunch()
	} else {
		browserURL = launcher.New().Headless(true).MustLaunch()
	}

	b.Browser = rod.New().ControlURL(browserURL).MustConnect()
}

func (b *BrowserPageCapturer) Close(ctx context.Context) error {
	svc1log.FromContext(ctx).Debug("Closing browser with allowed timeout of 5 seconds")
	if b.Browser != nil {
		svc1log.FromContext(ctx).Debug("Attempting to close browser")
		closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		closeChan := make(chan error)
		go func() {
			closeChan <- b.Browser.Close()
		}()

		select {
		case err := <-closeChan:
			if err != nil {
				svc1log.FromContext(ctx).Error("Failed to close browser", svc1log.SafeParam("error", err))
				return err
			}
			svc1log.FromContext(ctx).Debug("Successfully closed browser")
		case <-closeCtx.Done():
			svc1log.FromContext(ctx).Warn("Timeout while closing browser, skipping close operation")
		}
	}
	return nil
}
