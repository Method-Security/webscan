package capture

import (
	"context"
	"encoding/base64"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/ysmood/gson"
)

func (b *BrowserbasePageCapturer) CaptureScreenshot(ctx context.Context, url string, options *Options) webscan.PageScreenshotReport {
	return b.Capturer.CaptureScreenshot(ctx, url, options)
}

func (b *BrowserPageCapturer) CaptureScreenshot(ctx context.Context, url string, options *Options) webscan.PageScreenshotReport {
	report := webscan.PageScreenshotReport{
		Target: url,
		Errors: []string{},
	}
	log := svc1log.FromContext(ctx)

	// Call the Capture function to get the HTML content
	captureResult, err := b.Capture(ctx, url, options)
	if err != nil {
		log.Error("Failed to capture HTML content", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	var encodedBodyString string
	if captureResult.Content != nil {
		encodedBodyString = base64.StdEncoding.EncodeToString(captureResult.Content)
	}

	if b.Browser == nil {
		log.Debug("Initializing browser")
		b.InitializeBrowser()
	}

	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	var page *rod.Page
	err = rod.Try(func() {
		page = b.Browser.MustPage(url).Context(pageCtx)
	})
	if err != nil {
		log.Error("Failed to create page", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return report
	}
	log.Debug("Successfully connected to page")

	// Navigate to the page
	err = page.Navigate(url)
	if err != nil {
		log.Error("Failed to navigate to page", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Wait for the DOM to be stable
	// Important for capturing dynamic content
	err = page.WaitDOMStable(time.Duration(b.MinDOMStabalizeTimeSeconds)*time.Second, .1)
	if err != nil {
		log.Debug("Failed to wait for page load", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		// Reload the page if it can't load, possible redirect
		reloadErr := page.Reload()
		if reloadErr != nil {
			log.Error("Failed to reload page", svc1log.SafeParam("url", url), svc1log.SafeParam("error", reloadErr))
			report.Errors = append(report.Errors, err.Error())
			return report
		}
	}

	img, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: gson.Int(100),
	})

	if err != nil {
		log.Debug("Failed to capture screenshot", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	report.Screenshot = &img
	report.HtmlEncoded = &encodedBodyString
	return report
}
