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

type Module interface {
	ModuleRun(target string, config *webscan.WebServerTypeConfig) (*webscan.Attempt, []string)
	AnalyzeResponse(response *webscan.ResponseUnion) bool
}

type Engine struct {
	Library       Module
	Config        *webscan.WebServerTypeConfig
	ApacheModules map[webscan.ProbeType]map[webscan.ModuleName]Module
	NginxModules  map[webscan.ProbeType]map[webscan.ModuleName]Module
}

func NewEngine(config *webscan.WebServerTypeConfig) *Engine {
	return &Engine{
		Config: config,
		ApacheModules: map[webscan.ProbeType]map[webscan.ModuleName]Module{
			webscan.ProbeTypeEnumeration: {
				webscan.ModuleNamePathTraversal:        &apacheEnumerationModules.PathTraversalLibrary{},
				webscan.ModuleNameXPoweredByHeaderGrab: &apacheEnumerationModules.XPoweredByHeaderGrabLibrary{},
			},
			webscan.ProbeTypeValidation: {
				webscan.ModuleNameRceModFile: &apacheValidationModules.RCEModFileLibrary{},
			},
		},
		NginxModules: map[webscan.ProbeType]map[webscan.ModuleName]Module{
			webscan.ProbeTypeEnumeration: {
				webscan.ModuleNamePathTraversal:                &nginxEnumerationModules.PathTraversalLibrary{},
				webscan.ModuleNameReverseProxyMisconfiguration: &nginxEnumerationModules.ReverseProxyCheckLibrary{},
			},
			webscan.ProbeTypeValidation: {
				webscan.ModuleNameBufferOverflowContentHeader: &nginxValidationModules.BufferOverflowContentHeaderLibrary{},
				webscan.ModuleNameCrlfInjection:               &nginxValidationModules.CRLFInjectionLibrary{},
			},
		},
	}
}

func (e *Engine) GetModules() (map[webscan.ModuleName]Module, error) {
	switch e.Config.Server {
	case webscan.ServerTypeApache:
		return e.ApacheModules[e.Config.Probe], nil
	case webscan.ServerTypeNginx:
		return e.NginxModules[e.Config.Probe], nil
	default:
		return nil, fmt.Errorf("unsupported module: %s", e.Config.Server)
	}
}

func (e *Engine) Run(ctx context.Context, target string) (*webscan.Attempt, []string) {
	attempt, errs := e.Library.ModuleRun(target, e.Config)
	return attempt, errs
}

func (e *Engine) Launch(ctx context.Context) (*webscan.WebServerReport, error) {
	resources := webscan.WebServerReport{Server: e.Config.Server, Probe: e.Config.Probe}
	errors := []string{}

	moduleLibs, err := e.GetModules()
	if err != nil {
		return nil, err
	}

	var WebServers []*webscan.WebServer
	for _, target := range e.Config.Targets {
		var attempts []*webscan.Attempt
		for _, moduleLib := range moduleLibs {
			// Set current module library in the engine
			e.Library = moduleLib

			// Marshal Attempt results
			attempt, errs := e.Run(ctx, target)
			attempts = append(attempts, attempt)
			errors = append(errors, errs...)
		}

		if e.Config.SuccessfulOnly {
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
