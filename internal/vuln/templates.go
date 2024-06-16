// Package vuln is responsible for wrapping nuclei in order to manage the custom templates that are used within the webscan
// tool. This package is used to load custom templates, build template filters, and execute the nuclei tool against a target
// to identify vulnerabilities.
package vuln

import (
	"context"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
)

// LoadCustomTemplates loads custom templates from the provided customTemplatePath and the default templates directory.
// Updating the NuclieSDKOptions instance with the custom templates loaded.
func LoadCustomTemplates(ctx context.Context, customTemplatePath string) nuclei.NucleiSDKOptions {
	templateSources := nuclei.TemplateSources{Templates: []string{customTemplatePath, nuclei.DefaultConfig.TemplatesDirectory}}

	return nuclei.WithTemplatesOrWorkflows(templateSources)
}

// BuildTemplateFilters builds template filters based on the provided tags and severity, updating the
// NucleiSDKOptions instance with the template filters.
func BuildTemplateFilters(ctx context.Context, tags []string, severity string) nuclei.NucleiSDKOptions {
	return nuclei.WithTemplateFilters(nuclei.TemplateFilters{Severity: severity, Tags: tags})
}
