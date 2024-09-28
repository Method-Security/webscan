package capture

import (
	"context"

	"github.com/Method-Security/webscan/internal/browserbase"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type BrowserbaseWebpageCapturer struct {
	Client   *browserbase.Client
	Capturer *BrowserWebpageCapturer
}

func NewBrowserbaseWebpageCapturer(
	ctx context.Context,
	timeout int,
	browserbaseClient *browserbase.Client,
) *BrowserbaseWebpageCapturer {
	session, err := browserbaseClient.CreateSession(ctx)
	if err != nil {
		svc1log.FromContext(ctx).Error("Failed to create session. Aborting.")
		return nil
	}

	websocket := NewWebSocket(ctx, browserbaseClient.ConnectionString(*session))
	client := cdp.New().Start(websocket)
	return &BrowserbaseWebpageCapturer{
		Capturer: NewBrowserWebpageCapturerWithClient(client, timeout),
		Client:   browserbaseClient,
	}
}

func (b *BrowserbaseWebpageCapturer) Capture(ctx context.Context, url string, options *Options) (*Result, error) {
	return b.Capturer.Capture(ctx, url, options)
}

func (b *BrowserbaseWebpageCapturer) Close(ctx context.Context) error {
	var err error = nil
	sessionErr := b.Client.CloseAllSessions(ctx)
	if sessionErr != nil {
		svc1log.FromContext(ctx).Error("Failed to close all sessions")
		err = sessionErr
	}
	captureErr := b.Capturer.Close(ctx)
	if captureErr != nil {
		svc1log.FromContext(ctx).Error("Failed to close browser capturer")
		err = captureErr
	}
	return err
}
