package cmd

import (
	"github.com/Method-Security/webscan/internal/fuzz"
	"github.com/spf13/cobra"
)

// InitFuzzCommand initializes the fuzz command for the webscan CLI. This command is used to perform a web fuzz against a target.
func (a *WebScan) InitFuzzCommand() {
	a.FuzzCmd = &cobra.Command{
		Use:   "fuzz",
		Short: "Perform a web fuzz against a target",
		Long:  `Perform a web fuzz against a target`,
	}

	pathCmd := &cobra.Command{
		Use:   "path",
		Short: "Perform a path based web fuzz against a target",
		Long:  `Perform a path based web fuzz against a target`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			pathlist, err := cmd.Flags().GetString("pathlist")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			ignorebase, err := cmd.Flags().GetBool("ignore-base-content-match")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			responsecodes, err := cmd.Flags().GetString("responsecodes")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			maxtime, err := cmd.Flags().GetInt("maxtime")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			var report fuzz.PathReport
			report, err = fuzz.PerformPathFuzz(cmd.Context(), target, pathlist, ignorebase, responsecodes, maxtime)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report

		},
	}

	pathCmd.Flags().String("target", "", "URL target to perform path fuzzing against")
	pathCmd.Flags().String("pathlist", "", "Newline separated list of paths to fuzz")
	pathCmd.Flags().String("responsecodes", "200-299", "Response codes to consider as valid responses")
	pathCmd.Flags().Bool("ignore-base-content-match", true, "Ignores valid responses with identical size and word length to the base path, typically signifying a web backend redirect")
	pathCmd.Flags().Int("maxtime", 300, "The maximum time in seconds to run the job, default to 300 seconds")

	a.FuzzCmd.AddCommand(pathCmd)
	a.RootCmd.AddCommand(a.FuzzCmd)
}
