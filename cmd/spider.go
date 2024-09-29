package cmd

import (
	"bufio"
	"errors"
	"os"

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

	bodyGrabCmd := &cobra.Command{
		Use:   "bodygrab",
		Short: "Given a Url grab the response body",
		Long:  `Given a Url grab the response body`,
		Run: func(cmd *cobra.Command, args []string) {
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			filePaths, err := cmd.Flags().GetStringSlice("files")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			fileTargets, err := getTargetsFromFiles(filePaths)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			allTargets := append(targets, fileTargets...)

			if len(allTargets) == 0 {
				err = errors.New("no targets specified")
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			setHTTP, err := cmd.Flags().GetBool("https")
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

			report, err := spider.BodyGrab(allTargets, setHTTP, timeout)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	bodyGrabCmd.Flags().StringSlice("targets", []string{}, "URL targets to analyze")
	bodyGrabCmd.Flags().StringSlice("files", []string{}, "Paths to files containing the list of targets")
	bodyGrabCmd.Flags().Bool("https", false, "Only check sites with secure SSL")
	bodyGrabCmd.Flags().Int("timeout", 10, "Request timeout in seconds")

	spiderCmd.AddCommand(bodyGrabCmd)

	a.RootCmd.AddCommand(spiderCmd)
}

func getTargetsFromFiles(paths []string) ([]string, error) {
	targets := []string{}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		err = file.Close()
		if err != nil {
			return nil, err
		}
		var lines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		targets = append(targets, lines...)
	}
	return targets, nil
}
