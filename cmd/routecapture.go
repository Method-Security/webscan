package cmd

import (
	webscan "github.com/Method-Security/webscan/generated/go"
	routecapture "github.com/Method-Security/webscan/internal/routecapture"
	"github.com/spf13/cobra"
)

// InitRoutecaptureCommand initializes the Routecapture command for the webscan CLI. This command is used to collect
// the HTML of a webpage from a URL target.
func (a *WebScan) InitRoutecaptureCommand() {
	routeCaptureCmd := &cobra.Command{
		Use:   "routecapture",
		Short: "Perform a webpage routes and URL links capture against a URL target",
		Long:  `Perform a webpage routes and URL links capture against a URL target`,
	}
	routeCaptureCmd.PersistentFlags().String("target", "", "URL target to perform webpage capture")
	routeCaptureCmd.PersistentFlags().String("browserPath", "", "Path to a browser executable")
	routeCaptureCmd.PersistentFlags().Bool("base-urls-only", true, "Only match routes and urls that share the base URLs domain")
	routeCaptureCmd.PersistentFlags().Int("timeout", 30, "Timeout in seconds for the capture")

	requestCaptureCmd := &cobra.Command{
		Use:   "request",
		Short: "Perform a webpage HTML capture using a basic HTTP/HTTPS request",
		Long:  `Perform a webpage HTML capture using a basic HTTP/HTTPS request`,
		Run: func(cmd *cobra.Command, args []string) {
			insecure, _ := cmd.Flags().GetBool("insecure")

			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			var browserPath *string
			if path, err := cmd.Flags().GetString("browserPath"); err == nil {
				if path != "" {
					browserPath = &path
				}
			} else {
				a.OutputSignal.AddError(err)
				return
			}

			baseURLsOnly, _ := cmd.Flags().GetBool("base-urls-only")

			timeout, _ := cmd.Flags().GetInt("timeout")

			// Extract the routes and links
			report := routecapture.PerformRouteCapture(cmd.Context(), target, webscan.PageCaptureMethodRequest, baseURLsOnly, timeout, insecure, browserPath)
			a.OutputSignal.Content = report
		},
	}
	requestCaptureCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	routeCaptureCmd.AddCommand(requestCaptureCmd)

	browserCaptureCmd := &cobra.Command{
		Use:   "browser",
		Short: "Perform a webpage HTML capture using a headless browser",
		Long:  `Perform a webpage HTML capture using a headless browser`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			baseURLsOnly, _ := cmd.Flags().GetBool("base-urls-only")

			var browserPath *string
			if path, err := cmd.Flags().GetString("browserPath"); err == nil {
				if path != "" {
					browserPath = &path
				}
			} else {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, _ := cmd.Flags().GetInt("timeout")

			// Extract the routes and links
			report := routecapture.PerformRouteCapture(cmd.Context(), target, webscan.PageCaptureMethodBrowser, baseURLsOnly, timeout, false, browserPath)
			a.OutputSignal.Content = report
		},
	}
	browserCaptureCmd.PersistentFlags().String("browserPath", "", "Path to a browser executable")
	routeCaptureCmd.AddCommand(browserCaptureCmd)

	a.RootCmd.AddCommand(routeCaptureCmd)
}
