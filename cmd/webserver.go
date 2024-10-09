package cmd

import (
	"fmt"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
	webserver "github.com/Method-Security/webscan/internal/webserver"
	webservertype "github.com/Method-Security/webscan/internal/webserver/type"
	"github.com/spf13/cobra"
)

// InitWebServerCommand initializes the probe command for the webscan CLI. This command is used to perform a web probe against
// targets to identify the existence of web servers.
func (a *WebScan) InitWebServerCommand() {
	webServerCmd := &cobra.Command{
		Use:   "webserver",
		Short: "Perform webserver analysis",
		Long:  `Perform webserver analysis`,
	}

	probeCmd := &cobra.Command{
		Use:   "probe",
		Short: "Perform a web probe against targets to identify existence of web servers",
		Long:  `Perform a web probe against targets to identify existence of web servers`,
		Run: func(cmd *cobra.Command, args []string) {
			targets, err := cmd.Flags().GetString("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := webserver.PerformWebServerProbe(cmd.Context(), targets, time.Duration(timeout)*time.Second)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report

		},
	}

	probeCmd.Flags().String("targets", "", "Address targets to perform webserver probing agains, comma delimited list")
	probeCmd.Flags().Int("timeout", 30, "Timeout limit in seconds")

	webServerCmd.AddCommand(probeCmd)

	enumerationCmd := &cobra.Command{
		Use:   "enumeration",
		Short: "Enumerate a specific type of web server",
		Long:  `Enumerate a specific type of web server`,
		Run: func(cmd *cobra.Command, args []string) {
			// Targets
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// ServerType
			server, err := cmd.Flags().GetString("server")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			serverEnum, err := webscan.NewServerTypeFromString(strings.ToUpper(server))
			if err != nil {
				a.OutputSignal.AddError(fmt.Errorf("invalid server type '%s': must be either 'APACHE' or 'NGINX'", server))
				return
			}

			// Run Configs
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successfulonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			config, err := NewLoadWebserverTypeConfig(targets, serverEnum, webscan.ProbeTypeEnumeration, timeout, successfulOnly)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := webservertype.TypeLaunch(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report

		},
	}

	enumerationCmd.Flags().StringSlice("targets", []string{}, "Address of target")
	enumerationCmd.Flags().String("server", "", "Server type to target (nginx, apache)")
	enumerationCmd.Flags().Int("timeout", 5000, "Timeout limit in milliseconds")
	enumerationCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")

	_ = enumerationCmd.MarkFlagRequired("targets")
	_ = enumerationCmd.MarkFlagRequired("server")

	webServerCmd.AddCommand(enumerationCmd)

	a.RootCmd.AddCommand(webServerCmd)

	validationCmd := &cobra.Command{
		Use:   "validation",
		Short: "Preform validation against a specific type of web server",
		Long:  `Preform validation against a specific type of web server`,
		Run: func(cmd *cobra.Command, args []string) {
			// Targets
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// ServerType
			server, err := cmd.Flags().GetString("server")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			serverEnum, err := webscan.NewServerTypeFromString(strings.ToUpper(server))
			if err != nil {
				a.OutputSignal.AddError(fmt.Errorf("invalid server type '%s': must be either 'APACHE' or 'NGINX'", server))
				return
			}

			// Run Configs
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successfulonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			config, err := NewLoadWebserverTypeConfig(targets, serverEnum, webscan.ProbeTypeValidation, timeout, successfulOnly)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := webservertype.TypeLaunch(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report

		},
	}

	validationCmd.Flags().StringSlice("targets", []string{}, "Address of target")
	validationCmd.Flags().String("server", "", "Server type to target (nginx, apache)")
	validationCmd.Flags().Int("timeout", 5000, "Timeout limit in milliseconds")
	validationCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")

	_ = validationCmd.MarkFlagRequired("targets")
	_ = validationCmd.MarkFlagRequired("server")

	webServerCmd.AddCommand(validationCmd)

	a.RootCmd.AddCommand(webServerCmd)
}

func NewLoadWebserverTypeConfig(targets []string, serverEnum webscan.ServerType, probeEnum webscan.ProbeType, timeout int, successfulOnly bool) (*webscan.WebServerTypeConfig, error) {
	config := &webscan.WebServerTypeConfig{
		Targets:        targets,
		Probe:          probeEnum,
		Server:         serverEnum,
		Timeout:        timeout,
		SuccessfulOnly: successfulOnly,
	}
	if config.Timeout < 1 {
		config.Timeout = 0
	}
	return config, nil
}
