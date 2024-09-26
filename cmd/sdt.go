package cmd

import (
	"github.com/Method-Security/webscan/internal/sdt"
	"github.com/Method-Security/webscan/internal/sdt/runner"
	"github.com/spf13/cobra"
)

var opts = runner.Config{}

func (a *WebScan) InitSdtCommand() {
	sdtCmd := &cobra.Command{
		Use:   "sdt",
		Short: "Perform validation of URL target for potential subdomain takeover",
		Long:  `Perform validation of URL target for potential subdomain takeover`,
		Run: func(cmd *cobra.Command, args []string) {

			report, err := sdt.AnalyzeSDT(&opts)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	sdtCmd.Flags().StringVar(&opts.Target, "target", "", "Comma separated list of domains")
	sdtCmd.Flags().StringVar(&opts.Targets, "targets", "", "File containing the list of subdomains")
	sdtCmd.Flags().BoolVar(&opts.HTTPS, "https", false, "Force https protocol if not no protocol defined for target (default false)")
	sdtCmd.Flags().BoolVar(&opts.VerifySSL, "verify_ssl", false, "If set to true it won't check sites with insecure SSL and return HTTP Error")
	sdtCmd.Flags().BoolVar(&opts.HideFails, "hide_fails", false, "Don't display failed results")
	sdtCmd.Flags().BoolVar(&opts.OnlyVuln, "vuln", false, "Save only vulnerable subdomains")
	sdtCmd.Flags().IntVar(&opts.Concurrency, "concurrency", 10, "Number of concurrent checks")
	sdtCmd.Flags().IntVar(&opts.Timeout, "timeout", 10, "Request timeout in seconds")
	a.RootCmd.AddCommand(sdtCmd)
}
