package cmd

import (
	"github.com/Method-Security/webscan/internal/fingerprint"
	"github.com/spf13/cobra"
)

// InitFingerprintCommand initializes the fingerprint command for the webscan CLI. This command is used to perform a fingerprint
// against a URL target, capturing data TLS and HTTP methods that exist on the URL.
func (a *WebScan) InitFingerprintCommand() {
	fingerprintCmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Perform a fingerprint against a URL target",
		Long:  `Perform a fingerprint against a URL target`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report := fingerprint.PerformFingerprint(cmd.Context(), target)

			a.OutputSignal.Content = report
		},
	}

	fingerprintCmd.Flags().String("target", "", "Url target to perform fingerprint")

	a.RootCmd.AddCommand(fingerprintCmd)
}
