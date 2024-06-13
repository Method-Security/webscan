package cmd

import (
	"github.com/Method-Security/webscan/internal/probe"
	"github.com/spf13/cobra"
)

func (a *WebScan) InitProbeCommand() {
	a.ProbeCmd = &cobra.Command{
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

			report, err := probe.PerformWebServerProbe(cmd.Context(), targets)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report

		},
	}

	webserverCmd.Flags().String("targets", "", "Address targets to perform webserver probing agains, comma delimited list")

	a.ProbeCmd.AddCommand(webserverCmd)
	a.RootCmd.AddCommand(a.ProbeCmd)
}
