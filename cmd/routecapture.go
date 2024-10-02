package cmd

import (
	"github.com/spf13/cobra"
)

// InitRoutecaptureCommand initializes the Routecapture command for the webscan CLI. This command is used to collect
// the HTML of a webpage from a URL target.
func (a *WebScan) InitRoutecaptureCommand() {
	routeCaptureCmd := &cobra.Command{
		Use:   "routecapture",
		Short: "Perform a webpage routes and URL links capture against a URL target",
		Long:  `Perform a webpage routes and URL links capture against a URL targett`,
	}
	routeCaptureCmd.PersistentFlags().String("target", "", "URL target to perform routes capture")
	routeCaptureCmd.PersistentFlags().Int("timeout", 30, "Timeout in seconds for the capture")
}
