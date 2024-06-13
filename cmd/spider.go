package cmd

import (
	"github.com/Method-Security/webscan/internal/spider"
	"github.com/spf13/cobra"
)

func (a *WebScan) InitSpiderCommand() {
	a.SpiderCmd = &cobra.Command{
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

	a.SpiderCmd.Flags().String("targets", "", "Url targets to perform web spidering, comma delimited list")

	a.RootCmd.AddCommand(a.SpiderCmd)
}
