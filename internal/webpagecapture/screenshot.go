package webpagecapture

import (
	"context"
	"encoding/base64"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
	"github.com/chromedp/chromedp"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
)

func PerformWebpageScreenshot(ctx context.Context, path string, target string) webscan.WebpageScreenshotReport {
	var browserUrl string
	if path != "" {
		browserUrl = launcher.New().Headless(true).Bin(path).MustLaunch()
	} else {
		browserUrl = launcher.New().Headless(true).MustLaunch()
	}
	browser := rod.New().ControlURL(browserUrl).MustConnect()
	defer browser.MustClose()

	img, err := browser.MustPage(target).MustWaitStable().ScrollScreenshot(&rod.ScrollScreenshotOptions{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: gson.Int(100),
	})
	if err != nil {
		return webscan.WebpageScreenshotReport{
			Target: target,
			Errors: []string{err.Error()},
		}
	}

	return webscan.WebpageScreenshotReport{
		Target:     target,
		Screenshot: img,
		Errors:     nil,
	}
}

func PerformChromeDpWebpageScreenshot(ctx context.Context, target string, noSandbox bool) (string, error) {
	opts := chromedp.DefaultExecAllocatorOptions[:]
	if noSandbox {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}

	ctx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx, chromedp.WithLogf(func(string, ...interface{}) {}))
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var buf []byte
	if err := chromedp.Run(ctx, fullScreenshot(target, 100, &buf)); err != nil {
		return "", err
	}
	encodedImg := base64.StdEncoding.EncodeToString(buf)
	return encodedImg, nil
}

// fullScreenshot takes a screenshot of the entire browser viewport.
//
// Note: chromedp.FullScreenshot overrides the device's emulation settings. Use
// device.Reset to reset the emulation and viewport settings.
func fullScreenshot(urlstr string, quality int, res *[]byte) chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Navigate(urlstr),
		chromedp.FullScreenshot(res, quality),
	}
}
