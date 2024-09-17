package cmd

import (
	"github.com/Method-Security/webscan/internal/webpagecapture"
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

	webpagecaptureCmd.AddCommand(webpageScreenshotCmd)
	a.RootCmd.AddCommand(webpagecaptureCmd)
}
