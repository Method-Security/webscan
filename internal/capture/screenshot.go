package capture

import (
	"context"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/ysmood/gson"
)

func (b *BrowserPageCapturer) CaptureScreenshot(ctx context.Context, url string, options *Options) webscan.PageScreenshotReport {
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
		return webscan.PageScreenshotReport{
			Target: url,
			Errors: []string{err.Error()},
		}
	}
	log.Debug("Successfully connected to page")

	page = page.MustWaitDOMStable()

	img, err := page.MustWaitStable().ScrollScreenshot(&rod.ScrollScreenshotOptions{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: gson.Int(100),
	})
	if err != nil {
		return webscan.PageScreenshotReport{
			Target: url,
			Errors: []string{err.Error()},
		}
	}

	return webscan.PageScreenshotReport{
		Target:     url,
		Screenshot: img,
		Errors:     nil,
	}
}
