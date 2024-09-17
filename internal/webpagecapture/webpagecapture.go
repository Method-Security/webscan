package webpagecapture

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
	"github.com/chromedp/chromedp"
)

// PerformWebpageCapture performs a webpage capture against a target URL
func PerformWebpageCapture(ctx context.Context, noSandbox bool, target string) (*webscan.WebpageCaptureReport, error) {
	report := &webscan.WebpageCaptureReport{
		Target: target,
	}

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

	// Fetch the fully rendered HTML content
	body, err := fetchHTMLContent(ctx, target)
	if err != nil {
		return report, err
	}
	encodedBodyString := base64.StdEncoding.EncodeToString([]byte(body))
	report.HtmlEncoded = &encodedBodyString
	return report, nil
}

func fetchHTMLContent(ctx context.Context, target string) (string, error) {
	var body string
	err := chromedp.Run(ctx,
		chromedp.Navigate(target),
		chromedp.OuterHTML("html", &body),
	)
	if err != nil {
		return "", fmt.Errorf("failed to fetch HTML: %v", err)
	}
	return body, nil
}
