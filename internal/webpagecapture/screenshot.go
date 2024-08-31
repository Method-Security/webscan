package webpagecapture

import (
	"context"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
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

	pageCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var page *rod.Page
	err := rod.Try(func() {
		page = browser.MustPage(target).Context(pageCtx)
	})
	if err != nil {
		errorMsg := err.Error()
		if strings.Contains(errorMsg, "net::ERR_NAME_NOT_RESOLVED") {
			errorMsg = "Unable to resolve the domain name. Please check if the URL is correct and the domain exists."
		} else {
			errorMsg = "Failed to load the page: " + errorMsg
		}
		return webscan.WebpageScreenshotReport{
			Target: target,
			Errors: []string{errorMsg},
		}
	}

	img, err := page.MustWaitStable().ScrollScreenshot(&rod.ScrollScreenshotOptions{
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
