package vuln

import (
	"context"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type VulnerabilityContext struct {
	TemplateID       string   `json:"template-id"`
	Host             string   `json:"host"`
	URL              string   `json:"url"`
	Port             string   `json:"port"`
	FullPath         string   `json:"full-path"`
	ExtractedResults []string `json:"extracted-results"`
}

type VulnerabilityFinding struct {
	ID      string               `json:"id"`
	Info    model.Info           `json:"info"`
	Context VulnerabilityContext `json:"context"`
}

type VulnerabilityReport struct {
	Target  string                 `json:"target"`
	Reports []VulnerabilityFinding `json:"report"`
}

func parseResultIntoContext(result nucleiOutput.ResultEvent) VulnerabilityContext {
	return VulnerabilityContext{URL: result.Host, Port: result.Port, FullPath: result.Matched, Host: result.Host, TemplateID: result.TemplateID, ExtractedResults: result.ExtractedResults}
}

func buildID(result nucleiOutput.ResultEvent) string {
	return result.Matched + "-" + result.TemplateID
}

func parseResultIntoFinding(result nucleiOutput.ResultEvent) VulnerabilityFinding {
	return VulnerabilityFinding{ID: buildID(result), Info: result.Info, Context: parseResultIntoContext(result)}
}

func PerformVulnScan(ctx context.Context, target string, tags []string, severity string, templateDirectory string, customTemplateDirectory string) (VulnerabilityReport, error) {
	report := VulnerabilityReport{Target: target}
	if templateDirectory != "" {
		nuclei.DefaultConfig.TemplatesDirectory = templateDirectory
	}
	ne, err := nuclei.NewNucleiEngine(BuildTemplateFilters(ctx, tags, severity), LoadCustomTemplates(ctx, customTemplateDirectory))
	if err != nil {
		return VulnerabilityReport{}, err
	}
	err = ne.LoadAllTemplates()
	if err != nil {
		return VulnerabilityReport{}, err
	}
	ne.LoadTargets([]string{target}, true)
	results := []nucleiOutput.ResultEvent{}
	err = ne.ExecuteCallbackWithCtx(ctx, func(event *nucleiOutput.ResultEvent) {
		results = append(results, *event)
	})
	if err != nil {
		return VulnerabilityReport{}, err
	}
	defer ne.Close()
	for _, result := range results {
		vulnReport := parseResultIntoFinding(result)
		report.Reports = append(report.Reports, vulnReport)
	}
	return report, nil
}
