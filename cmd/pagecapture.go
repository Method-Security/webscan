package cmd

import (
	"fmt"
	"os"

	"github.com/Method-Security/webscan/internal/browserbase"
	capture "github.com/Method-Security/webscan/internal/capture"
	"github.com/Method-Security/webscan/internal/webpagecapture"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// InitPagecaptureCommand initializes the pagecapture command for the webscan CLI. This command is used to collect
// the HTML of a webpage from a URL target.
func (a *WebScan) InitPagecaptureCommand() {
	pagecaptureCmd := &cobra.Command{
		Use:     "pagecapture",
		Aliases: []string{"capture"},
		Short:   "Perform a webpage capture against a URL target",
		Long:    `Perform a webpage capture against a URL target`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			noSandbox, err := cmd.Flags().GetBool("no-sandbox")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report, err := webpagecapture.PerformWebpageCapture(cmd.Context(), noSandbox, target)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	pagecaptureCmd.Flags().String("target", "", "Url target to perform webpage HTML capture")
	pagecaptureCmd.Flags().Bool("no-sandbox", false, "Disable sandbox mode for scan")

	var chromiumPath string
	pageScreenshotCmd := &cobra.Command{
		Use:   "screenshot",
		Short: "Perform a fully rendered webpage screenshot capture using a headless browser",
		Long:  `Perform a fully rendered webpage screenshot capture using a headless browser`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report := webpagecapture.PerformWebpageScreenshot(cmd.Context(), chromiumPath, target)
			a.OutputSignal.Content = report
		},
	}

	pageScreenshotCmd.Flags().String("target", "", "Url target to perform webpage screenshot")
	pageScreenshotCmd.Flags().StringVar(&chromiumPath, "chromium-path", "", "Path to an instance of Chromium to use for the screenshot")

	htmlCaptureCmd := &cobra.Command{
		Use: "html",
		Short: "Perform a webpage HTML capture against a URL target",
		Long: `Perform a webpage HTML capture against a URL target`,
	}
	htmlCaptureCmd.PersistentFlags().String("target", "", "URL target to perform webpage capture")
	htmlCaptureCmd.PersistentFlags().Int("timeout", 30, "Timeout in seconds for the capture")

	requestCaptureCmd := &cobra.Command{
		Use: "request",
		Short: "Perform a webpage HTML capture using a basic HTTP/HTTPS request",
		Long: `Perform a webpage HTML capture using a basic HTTP/HTTPS request`,
		Run: func(cmd *cobra.Command, args []string) {
			log := svc1log.FromContext(cmd.Context())
			insecure, _ := cmd.Flags().GetBool("insecure")
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			capturer := capture.NewRequestWebpageCapturer(insecure)
			result, err := capturer.Capture(cmd.Context(), target, &capture.Options{})
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			_ = capturer.Close(cmd.Context())
			log.Info("Webpage capture successful", svc1log.SafeParam("target", target))
			a.OutputSignal.Content = result.ToWebpageCaptureReport()
		},
	}
	requestCaptureCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	htmlCaptureCmd.AddCommand(requestCaptureCmd)

	browserCaptureCmd := &cobra.Command{
		Use: "browser",
		Short: "Perform a fully rendered webpage HTML capture using a headless browser",
		Long: `Perform a fully rendered webpage HTML capture using a headless browser`,
		Run: func(cmd *cobra.Command, args []string) {
			log := svc1log.FromContext(cmd.Context())

			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, _ := cmd.Flags().GetInt("timeout")

			capturer := capture.NewBrowserWebpageCapturer(nil, timeout)
			result, err := capturer.Capture(cmd.Context(), target, &capture.Options{})
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			_ = capturer.Close(cmd.Context())
			log.Info("Webpage capture successful", svc1log.SafeParam("target", target))

			a.OutputSignal.Content = result.ToWebpageCaptureReport()
		},
	}
	htmlCaptureCmd.AddCommand(browserCaptureCmd)

	browserbaseCaptureCmd := &cobra.Command{
		Use: "browserbase",
		Short: "Perform a fully rendered webpage HTML capture using Browserbase",
		Long: `Perform a fully rendered webpage HTML capture using Browserbase. Useful for avoiding bot detection or maintaining stealth`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			countries, _ := cmd.Flags().GetStringArray("country")
			if len(countries) > 0 {
				_ = cmd.MarkFlagRequired("proxy")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			log := svc1log.FromContext(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			token, err := getFlagOrEnvironmentVariable(cmd, "token", "BROWSERBASE_TOKEN")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			project, err := getFlagOrEnvironmentVariable(cmd, "project", "BROWSERBASE_PROJECT")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, _ := cmd.Flags().GetInt("timeout")
			proxy, _ := cmd.Flags().GetBool("proxy")
			countries, _ := cmd.Flags().GetStringArray("country")

			var options []browserbase.Option
			if proxy && len(countries) > 0 {
				options = append(options, browserbase.WithProxyCountries(countries))
			} else if proxy {
				options = append(options, browserbase.WithProxy())
			}

			client := browserbase.NewBrowserbaseClient(token, project, browserbase.NewBrowserbaseOptions(cmd.Context(), options...))
			capturer := capture.NewBrowserbaseWebpageCapturer(cmd.Context(), timeout, client)

			if capturer == nil {
				a.OutputSignal.AddError(fmt.Errorf("failed to create browserbase capturer"))
				return
			}

			result, err := capturer.Capture(cmd.Context(), target, &capture.Options{})
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			_ = capturer.Close(cmd.Context())
			log.Info("Webpage capture successful", svc1log.SafeParam("target", target))
			a.OutputSignal.Content = result.ToWebpageCaptureReport()
		},
	}
	browserbaseCaptureCmd.Flags().String("token", "", "Browserbase API token")
	browserbaseCaptureCmd.Flags().String("project", "", "Browserbase project ID")
	browserbaseCaptureCmd.Flags().Bool("proxy", false, "Instruct Browserbase to use a proxy")
	browserbaseCaptureCmd.Flags().StringArray("country", []string{}, "List of countries to use for the proxy")

	htmlCaptureCmd.AddCommand(browserbaseCaptureCmd)

	pagecaptureCmd.AddCommand(htmlCaptureCmd)
	pagecaptureCmd.AddCommand(pageScreenshotCmd)
	a.RootCmd.AddCommand(pagecaptureCmd)
}

// TODO: We could likely move this to viper to streamline
func getFlagOrEnvironmentVariable(cmd *cobra.Command, flagName string, environmentVariableName string) (string, error) {
	var value string
	if envVar, exists := os.LookupEnv(environmentVariableName); exists && envVar != "" {
		value = envVar
	} else if flagValue, err := cmd.Flags().GetString(flagName); err == nil && flagValue != "" {
		value = flagValue
	} else {
		return "", fmt.Errorf("no value provided for %s", flagName)
	}

	return value, nil
}
