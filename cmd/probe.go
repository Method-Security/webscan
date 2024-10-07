package cmd

import (
	"errors"
	"fmt"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
	probe "github.com/Method-Security/webscan/internal/probe"
	probetype "github.com/Method-Security/webscan/internal/probe/type"
	"github.com/spf13/cobra"
)

// InitProbeCommand initializes the probe command for the webscan CLI. This command is used to perform a web probe against
// targets to identify the existence of web servers.
func (a *WebScan) InitProbeCommand() {
	probeCmd := &cobra.Command{
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

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report, err := probe.PerformWebServerProbe(cmd.Context(), targets, time.Duration(timeout)*time.Second)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report

		},
	}

	webserverCmd.Flags().String("targets", "", "Address targets to perform webserver probing agains, comma delimited list")
	webserverCmd.Flags().Int("timeout", 30, "Timeout limit in seconds")

	probeCmd.AddCommand(webserverCmd)

	typeCmd := &cobra.Command{
		Use:   "type",
		Short: "Perform type specific analysis on a web server",
		Long:  `Perform type specific analysis on a web server`,
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

			// ProbeType
			probe, err := cmd.Flags().GetString("probe")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			probeEnum, err := webscan.NewProbeTypeFromString(strings.ToUpper(probe))
			if err != nil {
				a.OutputSignal.AddError(fmt.Errorf("invalid probe type '%s': must be either 'ENUMERATION' or 'VALIDATION'", probe))
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
			config, err := LoadProbeTypeConfig(targets, serverEnum, probeEnum, timeout, successfulOnly)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := probetype.TypeLaunch(cmd.Context(), config)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report

		},
	}

	typeCmd.Flags().StringSlice("targets", []string{}, "Address of target")
	typeCmd.Flags().String("server", "", "Server type to target (nginx, apache)")
	typeCmd.Flags().String("probe", "enumeration", "Probe type use (enumeration or validation)")
	typeCmd.Flags().Int("timeout", 5000, "Timeout limit in milliseconds")
	typeCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")

	_ = typeCmd.MarkFlagRequired("targets")
	_ = typeCmd.MarkFlagRequired("server")

	webserverCmd.AddCommand(typeCmd)

	probeCmd.AddCommand(webserverCmd)

	a.RootCmd.AddCommand(probeCmd)
}

func LoadProbeTypeConfig(targets []string, serverEnum webscan.ServerType, probeEnum webscan.ProbeType, timeout int, successfulOnly bool) (*webscan.ProbeTypeConfig, error) {
	config := &webscan.ProbeTypeConfig{
		Targets:        targets,
		Server:         serverEnum,
		Probe:          probeEnum,
		Timeout:        timeout,
		SuccessfulOnly: successfulOnly,
	}
	if config.Timeout < 1 {
		return nil, errors.New("timeout must be greater than 0")
	}
	return config, nil
}
