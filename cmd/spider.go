package cmd

import (
	"github.com/Method-Security/webscan/internal/spider"
	"github.com/spf13/cobra"
)

// InitSpiderCommand initializes the spider command for the webscan CLI. This command is used to perform a web spider crawl
// against URL targets, capturing data about webpages and endpoints that exist on the target.
func (a *WebScan) InitSpiderCommand() {
	spiderCmd := &cobra.Command{
		Use:   "spider",
		Short: "Perform a web web spider crawl against URL targets",
		Long:  `Perform a web web spider crawl against URL targets`,
		Run: func(cmd *cobra.Command, args []string) {
			targets, err := cmd.Flags().GetString("targets")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report, err := spider.PerformWebSpider(cmd.Context(), targets)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	spiderCmd.Flags().String("targets", "", "Url targets to perform web spidering, comma delimited list")

	a.RootCmd.AddCommand(spiderCmd)
}
