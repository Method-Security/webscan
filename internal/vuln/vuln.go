package vuln

import (
	"context"
	"net"
	"net/url"
	"regexp"
	"strings"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// VulnerabilityContext represents an instance of a vulnerability, with all of the information needed to contextualize
// that particular vulnerability.
type VulnerabilityContext struct {
	TemplateID       string   `json:"template-id"`
	Host             string   `json:"host"`
	URL              string   `json:"url"`
	Port             string   `json:"port"`
	FullPath         string   `json:"full-path"`
	ExtractedResults []string `json:"extracted-results"`
}

// A VulnerabilityFinding represents a single vulnerability that was found during a vulnerability scan.
// The Context is included in each finding to simplify the data integration and automation process.
type VulnerabilityFinding struct {
	ID      string               `json:"id"`
	Info    model.Info           `json:"info"`
	Context VulnerabilityContext `json:"context"`
}

// A VulnerabilityReport represents a holistic report of all the vulnerabilities that were found during a vulnerability scan.
type VulnerabilityReport struct {
	Target  string                 `json:"target"`
	Reports []VulnerabilityFinding `json:"report"`
}

func isValidIP(ip string) bool {
	ipv4Pattern := `^([0-9]{1,3}\.){3}[0-9]{1,3}$`
	ipv6Pattern := `^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`
	matchIPv4, _ := regexp.MatchString(ipv4Pattern, ip)
	matchIPv6, _ := regexp.MatchString(ipv6Pattern, ip)

	return matchIPv4 || matchIPv6
}

func ipToAddress(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return "", err
	}
	return names[0], nil
}

func parseResultIntoContext(result nucleiOutput.ResultEvent) VulnerabilityContext {
	return VulnerabilityContext{URL: result.URL, Port: result.Port, FullPath: result.Matched, Host: result.Host, TemplateID: result.TemplateID, ExtractedResults: result.ExtractedResults}
}

func buildID(result nucleiOutput.ResultEvent) string {
	return result.Matched + "-" + result.TemplateID
}

func parseResultIntoFinding(result nucleiOutput.ResultEvent) VulnerabilityFinding {
	return VulnerabilityFinding{ID: buildID(result), Info: result.Info, Context: parseResultIntoContext(result)}
}

// PerformVulnScan performs a vulnerability scan against a target URL, using the provided tags and severity to filter the
// templates that are used in the scan. The scan uses the provided templateDirectory and customTemplateDirectory to load
// the templates that are used in the scan.
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
	// Parse the target URL to remove the protocol
	parsedURL, err := url.Parse(target)
	if err != nil {
		return VulnerabilityReport{}, err
	}
	address := strings.TrimPrefix(parsedURL.String(), parsedURL.Scheme+"://")

	// If target is an ip, convert to address
	if isValidIP(address) {
		humanReadableAddress, err := ipToAddress(address)
		if err == nil {
			address = humanReadableAddress
		}
	}

	ne.LoadTargets([]string{address}, true)
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
