package cmd

import (
	"time"

	"github.com/Method-Security/webscan/internal/probe"
	"github.com/spf13/cobra"
)

// InitProbeCommand initializes the probe command for the webscan CLI. This command is used to perform a web probe against
// targets to identify the existence of web servers.
func (a *WebScan) InitProbeCommand() {
	probeCmd := &cobra.Command{
		Use:   "probe",
		Short: "Perform a web probe against targets",
		Long:  `Perform a web probe against targets`,
	}

	webserverCmd := &cobra.Command{
		Use:   "webserver",
		Short: "Perform a web probe against targets to identify existence of web servers",
		Long:  `Perform a web probe against targets to identify existence of web servers`,
		Run: func(cmd *cobra.Command, args []string) {
			targets, err := cmd.Flags().GetString("targets")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report, err := probe.PerformWebServerProbe(cmd.Context(), targets, time.Duration(timeout)*time.Second)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report

		},
	}

	webserverCmd.Flags().String("targets", "", "Address targets to perform webserver probing agains, comma delimited list")
	webserverCmd.Flags().Int("timeout", 10, "Timeout limit in seconds")

	probeCmd.AddCommand(webserverCmd)
	a.RootCmd.AddCommand(probeCmd)
}
