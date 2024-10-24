package cmd

import (
	"errors"
	"strings"

	"github.com/Method-Security/webscan/internal/vuln"
	"github.com/spf13/cobra"
)

func parseSeverityIntoString(severity []string) string {
	if len(severity) == 0 {
		return ""
	}
	return strings.Join(severity, ",")
}

// InitVulnCommand initializes the vuln command for the webscan CLI. This command is used to perform a vulnerability scan
// against a target by leveraging Project Discovery's nuclei tool.
func (a *WebScan) InitVulnCommand() {
	vulnCmd := &cobra.Command{
		Use:   "vuln",
		Short: "Perform a vulnerability scan against a target using nuclei",
		Long:  `Perform a vulnerability scan against a target using nuclei`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			if target == "" {
				err = errors.New("target flag is required")
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			tags, err := cmd.Flags().GetStringSlice("tags")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			rawSeverity, err := cmd.Flags().GetStringSlice("severity")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			severity := parseSeverityIntoString(rawSeverity)
			defaultTemplateDirectory, err := cmd.Flags().GetString("defaultTemplateDirectory")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			customTemplateDirectory, err := cmd.Flags().GetString("customTemplateDirectory")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := vuln.PerformVulnScan(cmd.Context(), target, tags, severity, defaultTemplateDirectory, customTemplateDirectory)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	vulnCmd.Flags().String("target", "", "URL target to perform path fuzzing against")
	vulnCmd.Flags().StringSlice("tags", []string{}, "Tags to filter templates by")
	vulnCmd.Flags().StringSlice("severity", []string{}, "Severity to filter templates by")
	vulnCmd.Flags().String("defaultTemplateDirectory", "", "Directory to load default templates from")
	vulnCmd.Flags().String("customTemplateDirectory", "", "Directory to load custom templates from")

	a.RootCmd.AddCommand(vulnCmd)
}
