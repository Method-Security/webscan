package cmd

import (
	"github.com/Method-Security/webscan/internal/webpagecapture"
	"github.com/spf13/cobra"
)

// InitWebpagecaptureCommand initializes the webpagecapture command for the webscan CLI. This command is used to collect
// the HTML of a webpage from a URL target.
func (a *WebScan) InitWebpagecaptureCommand() {
	webpagecaptureCmd := &cobra.Command{
		Use:   "webpagecapture",
		Short: "Perform a webpage HTML capture against a URL target",
		Long:  `Perform a webpage HTML capture against a URL target`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report := webpagecapture.PerformWebpageCapture(cmd.Context(), target)

			a.OutputSignal.Content = report
		},
	}

	webpagecaptureCmd.Flags().String("target", "", "Url target to perform webpage HTML capture")

	a.RootCmd.AddCommand(webpagecaptureCmd)
}
