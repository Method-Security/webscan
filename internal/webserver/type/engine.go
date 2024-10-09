package webserver

import (
	"context"
	"fmt"

	webscan "github.com/Method-Security/webscan/generated/go"
	apacheEnumerationModules "github.com/Method-Security/webscan/internal/webserver/type/apache/enumeration"
	apacheValidationModules "github.com/Method-Security/webscan/internal/webserver/type/apache/validation"
	nginxEnumerationModules "github.com/Method-Security/webscan/internal/webserver/type/nginx/enumeration"
	nginxValidationModules "github.com/Method-Security/webscan/internal/webserver/type/nginx/validation"
)

type ModuleLibrary interface {
	ModuleRun(target string, config *webscan.WebServerTypeConfig) (*webscan.Attempt, []string)
	AnalyzeResponse(response *webscan.ResponseUnion) bool
}

type TypeEngine struct {
	Library ModuleLibrary
}

func (be *TypeEngine) Run(ctx context.Context, target string, config *webscan.WebServerTypeConfig) (*webscan.Attempt, []string) {
	attempt, errs := be.Library.ModuleRun(target, config)
	return attempt, errs
}

func TypeLaunch(ctx context.Context, config *webscan.WebServerTypeConfig) (*webscan.WebServerReport, error) {
	resources := webscan.WebServerReport{Server: config.Server, Probe: config.Probe}
	errors := []string{}

	var WebServers []*webscan.WebServer
	for _, target := range config.Targets {
		var attempts []*webscan.Attempt
		moduleLibs, err := returnModuleLibaries(config)
		if err != nil {
			return nil, err
		}
		for _, moduleLib := range moduleLibs {
			// Engine declaration
			engine := &TypeEngine{
				Library: moduleLib,
			}
			// Marshal Attempt results
			attempt, errs := engine.Run(ctx, target, config)
			attempts = append(attempts, attempt)
			errors = append(errors, errs...)
		}

		if config.SuccessfulOnly {
			successfulAttempts := []*webscan.Attempt{}
			for _, attempt := range attempts {
				if attempt.Finding {
					successfulAttempts = append(successfulAttempts, attempt)
				}
			}
			attempts = successfulAttempts
		}

		WebServer := webscan.WebServer{Target: target, Attempts: attempts}
		WebServers = append(WebServers, &WebServer)
	}

	// Marshal Report
	resources.WebServers = WebServers
	resources.Errors = errors
	return &resources, nil
}

func returnModuleLibaries(config *webscan.WebServerTypeConfig) (map[webscan.ModuleName]ModuleLibrary, error) {
	apacheModules := map[webscan.ProbeType]map[webscan.ModuleName]ModuleLibrary{
		webscan.ProbeTypeEnumeration: {
			webscan.ModuleNamePathTraversal:        &apacheEnumerationModules.PathTraversalLibrary{},
			webscan.ModuleNameXPoweredByHeaderGrab: &apacheEnumerationModules.XPoweredByHeaderGrabLibrary{},
		},
		webscan.ProbeTypeValidation: {
			webscan.ModuleNameRceModFile: &apacheValidationModules.RCEModFileLibrary{},
		},
	}
	nginxModules := map[webscan.ProbeType]map[webscan.ModuleName]ModuleLibrary{
		webscan.ProbeTypeEnumeration: {
			webscan.ModuleNamePathTraversal:                &nginxEnumerationModules.PathTraversalLibrary{},
			webscan.ModuleNameReverseProxyMisconfiguration: &nginxEnumerationModules.ReverseProxyCheckLibrary{},
		},
		webscan.ProbeTypeValidation: {
			webscan.ModuleNameBufferOverflowContentHeader: &nginxValidationModules.BufferOverflowContentHeaderLibrary{},
			webscan.ModuleNameCrlfInjection:               &nginxValidationModules.CRLFInjectionLibrary{},
		},
	}

	switch config.Server {
	case webscan.ServerTypeApache:
		return apacheModules[config.Probe], nil
	case webscan.ServerTypeNginx:
		return nginxModules[config.Probe], nil
	default:
		return nil, fmt.Errorf("unsupported module: %s", config.Server)
	}
}
