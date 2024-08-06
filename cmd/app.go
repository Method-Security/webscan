package cmd

import (
	"errors"
	"net/url"
	"strings"

	"github.com/Method-Security/webscan/internal/graphql"
	"github.com/Method-Security/webscan/internal/grpc"
	"github.com/Method-Security/webscan/internal/swagger"
	"github.com/Method-Security/webscan/internal/vuln"
	"github.com/spf13/cobra"
)

// InitAppCommand initializes the app command for the webscan CLI.
func (a *WebScan) InitAppCommand() {
	a.AppCmd = &cobra.Command{
		Use:   "app",
		Short: "Perform various application scans",
		Long:  `Perform various application scans such as fingerprinting and enumeration`,
	}

	a.RootCmd.AddCommand(a.AppCmd)
	a.initFingerprintCommand()
	a.initEnumerateCommand()
}

func (a *WebScan) initFingerprintCommand() {
	fingerprintCmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Perform a fingerprint scan against a target",
		Long:  `Perform a fingerprint scan against a target using specified types`,
		Run: func(cmd *cobra.Command, args []string) {
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

			// Remove protocol from target URL if present
			parsedURL, err := url.Parse(target)
			if err == nil && parsedURL.Scheme != "" {
				target = strings.TrimPrefix(target, parsedURL.Scheme+"://")
			}

			tags, err := cmd.Flags().GetStringSlice("tags")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			if len(tags) == 0 {
				tags = []string{"swagger", "k8s", "graphql", "grpc"}
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

	fingerprintCmd.Flags().String("target", "", "URL target to perform fingerprinting against")
	fingerprintCmd.Flags().StringSlice("tags", []string{}, "Tags to filter templates by")
	fingerprintCmd.Flags().StringSlice("severity", []string{}, "Severity to filter templates by")
	fingerprintCmd.Flags().String("defaultTemplateDirectory", "", "Directory to load default templates from")
	fingerprintCmd.Flags().String("customTemplateDirectory", "", "Directory to load custom templates from")

	a.AppCmd.AddCommand(fingerprintCmd)
}

func (a *WebScan) initEnumerateCommand() {
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Perform enumeration scans against a target",
		Long:  `Perform enumeration scans against a target using specified types`,
	}

	enumerateCmd.AddCommand(a.initSwaggerEnumerateCommand())
	enumerateCmd.AddCommand(a.initGrpcEnumerateCommand())
	enumerateCmd.AddCommand(a.initGraphqlEnumerateCommand())

	a.AppCmd.AddCommand(enumerateCmd)
}

func (a *WebScan) initSwaggerEnumerateCommand() *cobra.Command {
	swaggerCmd := &cobra.Command{
		Use:   "swagger",
		Short: "Perform a Swagger enumeration scan against a target",
		Long:  `Perform a Swagger enumeration scan against a target`,
		Run: func(cmd *cobra.Command, args []string) {
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
			report, err := swagger.PerformSwaggerScan(cmd.Context(), target)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	swaggerCmd.Flags().String("target", "", "URL target to perform Swagger enumeration against")
	return swaggerCmd
}

func (a *WebScan) initGrpcEnumerateCommand() *cobra.Command {
	grpcCmd := &cobra.Command{
		Use:   "grpc",
		Short: "Perform a gRPC enumeration scan against a target",
		Long:  `Perform a gRPC enumeration scan against a target`,
		Run: func(cmd *cobra.Command, args []string) {
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
			report, err := grpc.PerformGRPCScan(cmd.Context(), target)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	grpcCmd.Flags().String("target", "", "URL target to perform gRPC enumeration against")
	return grpcCmd
}

func (a *WebScan) initGraphqlEnumerateCommand() *cobra.Command {
	graphqlCmd := &cobra.Command{
		Use:   "graphql",
		Short: "Perform a GraphQL enumeration scan against a target",
		Long:  `Perform a GraphQL enumeration scan against a target`,
		Run: func(cmd *cobra.Command, args []string) {
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
			report, err := graphql.PerformGraphQLScan(cmd.Context(), target)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	graphqlCmd.Flags().String("target", "", "URL target to perform GraphQL enumeration against")
	return graphqlCmd
}
