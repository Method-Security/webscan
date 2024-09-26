package cmd

import (
	"fmt"

	capture "github.com/Method-Security/webscan/internal/capture"
	"github.com/Method-Security/webscan/internal/webpagecapture"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// InitWebpagecaptureCommand initializes the webpagecapture command for the webscan CLI. This command is used to collect
// the HTML of a webpage from a URL target.
func (a *WebScan) InitWebpagecaptureCommand() {
	webpagecaptureCmd := &cobra.Command{
		Use:     "webpagecapture",
		Aliases: []string{"capture"},
		Short:   "Perform a webpage HTML capture against a URL target",
		Long:    `Perform a webpage HTML capture against a URL target`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			noSandbox, err := cmd.Flags().GetBool("no-sandbox")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report, err := webpagecapture.PerformWebpageCapture(cmd.Context(), noSandbox, target)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	webpagecaptureCmd.Flags().String("target", "", "Url target to perform webpage HTML capture")
	webpagecaptureCmd.Flags().Bool("no-sandbox", false, "Disable sandbox mode for scan")

	var chromiumPath string
	webpageScreenshotCmd := &cobra.Command{
		Use:   "screenshot",
		Short: "Perform a webpage screenshot against a URL target",
		Long:  `Perform a webpage screenshot against a URL target`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report := webpagecapture.PerformWebpageScreenshot(cmd.Context(), chromiumPath, target)
			a.OutputSignal.Content = report
		},
	}

	webpageScreenshotCmd.Flags().String("target", "", "Url target to perform webpage screenshot")
	webpageScreenshotCmd.Flags().StringVar(&chromiumPath, "chromium-path", "", "Path to an instance of Chromium to use for the screenshot")

	htmlCaptureCmd := &cobra.Command{
		Use: "html",
	}
	htmlCaptureCmd.Flags().String("target", "", "URL target to perform webpage capture")
	htmlCaptureCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")

	requestCaptureCmd := &cobra.Command{
		Use: "request",
		Run: func(cmd *cobra.Command, args []string) {
			log := svc1log.FromContext(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			capturer := capture.NewRequestWebpageCapturer()
			report, err := capturer.Capture(cmd.Context(), target, &capture.Options{})
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			_ = capturer.Close()
			log.Info("Webpage capture successful", svc1log.SafeParam("target", target))
			a.OutputSignal.Content = report
		},
	}
	htmlCaptureCmd.AddCommand(requestCaptureCmd)

	browserCaptureCmd := &cobra.Command{
		Use: "browser",
		Run: func(cmd *cobra.Command, args []string) {
			log := svc1log.FromContext(cmd.Context())

			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, _ := cmd.Flags().GetInt("timeout")

			capturer := capture.NewBrowserWebpageCapturer(nil, timeout)
			report, err := capturer.Capture(cmd.Context(), target, &capture.Options{})
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			_ = capturer.Close()
			log.Info("Webpage capture successful", svc1log.SafeParam("target", target))
			a.OutputSignal.Content = report
		},
	}
	htmlCaptureCmd.AddCommand(browserCaptureCmd)

	browserbaseCaptureCmd := &cobra.Command{
		Use: "browserbase",
		Run: func(cmd *cobra.Command, args []string) {
			log := svc1log.FromContext(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			token, err := cmd.Flags().GetString("token")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, _ := cmd.Flags().GetInt("timeout")

			baseURL := "wss://connect.browserbase.com?apiKey=%s"
			capturer := capture.NewBrowserbaseWebpageCapturer(cmd.Context(), fmt.Sprintf(baseURL, token), timeout)

			report, err := capturer.Capture(cmd.Context(), target, &capture.Options{})
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			_ = capturer.Close()
			log.Info("Webpage capture successful", svc1log.SafeParam("target", target))
			a.OutputSignal.Content = report
		},
	}
	browserbaseCaptureCmd.Flags().String("token", "", "Browserbase API token")
	htmlCaptureCmd.AddCommand(browserbaseCaptureCmd)

	webpagecaptureCmd.AddCommand(htmlCaptureCmd)
	webpagecaptureCmd.AddCommand(webpageScreenshotCmd)
	a.RootCmd.AddCommand(webpagecaptureCmd)
}
