package probe

import (
	"context"
	"fmt"

	webscan "github.com/Method-Security/webscan/generated/go"
	apacheEnumerationModules "github.com/Method-Security/webscan/internal/probe/type/apache/enumeration"
	apacheValidationModules "github.com/Method-Security/webscan/internal/probe/type/apache/validation"
	nginxEnumerationModules "github.com/Method-Security/webscan/internal/probe/type/nginx/enumeration"
	nginxValidationModules "github.com/Method-Security/webscan/internal/probe/type/nginx/validation"
)

type ModuleLibrary interface {
	ModuleRun(target string, config *webscan.ProbeTypeConfig) (*webscan.Attempt, []string)
	AnalyzeResponse(response *webscan.ResponseUnion) bool
}

type TypeEngine struct {
	Library ModuleLibrary
}

func (be *TypeEngine) Run(ctx context.Context, target string, config *webscan.ProbeTypeConfig) (*webscan.Attempt, []string) {
	attempt, errs := be.Library.ModuleRun(target, config)
	return attempt, errs
}

func TypeLaunch(ctx context.Context, config *webscan.ProbeTypeConfig) (*webscan.WebserverProbeReport, error) {
	resources := webscan.WebserverProbeReport{Server: config.Server, Probe: config.Probe}
	errors := []string{}

	var WebserverProbes []*webscan.WebserverProbe
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

		WebserverProbe := webscan.WebserverProbe{Target: target, Attempts: attempts}
		WebserverProbes = append(WebserverProbes, &WebserverProbe)
	}

	// Marshal Report
	resources.WebserverProbes = WebserverProbes
	resources.Errors = errors
	return &resources, nil
}

func returnModuleLibaries(config *webscan.ProbeTypeConfig) (map[webscan.ModuleName]ModuleLibrary, error) {
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
