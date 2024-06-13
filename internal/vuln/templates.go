package vuln

import (
	"context"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
)

func LoadCustomTemplates(ctx context.Context, customTemplatePath string) nuclei.NucleiSDKOptions {
	templateSources := nuclei.TemplateSources{Templates: []string{customTemplatePath, nuclei.DefaultConfig.TemplatesDirectory}}

	return nuclei.WithTemplatesOrWorkflows(templateSources)
}

func BuildTemplateFilters(ctx context.Context, tags []string, severity string) nuclei.NucleiSDKOptions {
	return nuclei.WithTemplateFilters(nuclei.TemplateFilters{Severity: severity, Tags: tags})
}
