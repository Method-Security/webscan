package swagger

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
	"github.com/chromedp/chromedp"
	"github.com/pb33f/libopenapi"
	"github.com/pb33f/libopenapi/datamodel/high/base"
	v2 "github.com/pb33f/libopenapi/datamodel/high/v2"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
	"github.com/pb33f/libopenapi/orderedmap"
	"golang.org/x/net/html"
)

// PerformSwaggerScan performs a Swagger scan against a target URL and returns the report.
func PerformSwaggerScan(ctx context.Context, target string, noSandbox bool) webscan.RoutesReport {
	report := webscan.RoutesReport{Target: target}

	opts := chromedp.DefaultExecAllocatorOptions[:]
	if noSandbox {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}

	ctx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx, chromedp.WithLogf(func(string, ...interface{}) {}))
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Fetch the fully rendered HTML content
	body, err := fetchHTMLContent(ctx, target)
	if err != nil {
		errMsg := fmt.Sprintf("Error fetching HTML content: %v", err)
		report.Errors = append(report.Errors, errMsg)
		return report
	}

	// Parse the HTML to find the Swagger JSON link
	swaggerURL, err := findSwaggerURL(body, target)
	if err != nil {
		errMsg := fmt.Sprintf("Error finding Swagger URL: %v", err)
		report.Errors = append(report.Errors, errMsg)
		return report
	}

	report.SchemaUrl = &swaggerURL

	// Fetch the Swagger JSON
	bodyBytes, err := fetchSwaggerJSON(swaggerURL)
	if err != nil {
		errMsg := fmt.Sprintf("Error fetching Swagger JSON: %v", err)
		report.Errors = append(report.Errors, errMsg)
		return report
	}

	// Encode the raw body in base64 and add to the report
	report.Raw = base64.StdEncoding.EncodeToString(bodyBytes)

	// Create a new document from specification bytes
	document, err := libopenapi.NewDocument(bodyBytes)
	if err != nil {
		errMsg := fmt.Sprintf("Error creating new document: %v", err)
		report.Errors = append(report.Errors, errMsg)
		return report
	}

	// Determine if the document is Swagger (OpenAPI 2.0) or OpenAPI 3.0+
	var docType map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &docType); err != nil {
		errMsg := fmt.Sprintf("failed to unmarshal document type: %v", err)
		report.Errors = append(report.Errors, errMsg)
		return report
	}

	if version, ok := docType["swagger"]; ok && strings.HasPrefix(version.(string), "2") {
		versionStr := version.(string)
		report.Version = &versionStr
		err = handleSwaggerV2(document, &report)
	} else if version, ok := docType["openapi"]; ok && strings.HasPrefix(version.(string), "3") {
		versionStr := version.(string)
		report.Version = &versionStr
		err = handleOpenAPIV3(document, &report, target)
	} else {
		errMsg := "unsupported OpenAPI version"
		report.Errors = append(report.Errors, errMsg)
		return report
	}

	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	return report
}

func fetchHTMLContent(ctx context.Context, target string) (string, error) {
	var body string
	err := chromedp.Run(ctx,
		chromedp.Navigate(target),
		chromedp.OuterHTML("html", &body),
	)
	if err != nil {
		return "", fmt.Errorf("failed to fetch HTML: %v", err)
	}
	return body, nil
}

func findSwaggerURL(body, target string) (string, error) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML: %v", err)
	}

	var potentialURLs []string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, a := range n.Attr {
				if strings.Contains(a.Val, "swagger.json") || strings.Contains(a.Val, "openapi.json") {
					potentialURLs = append(potentialURLs, a.Val)
				}
			}
		}
		if n.Type == html.TextNode && n.Parent != nil && n.Parent.Data == "script" {
			if strings.Contains(n.Data, "swagger.json") || strings.Contains(n.Data, "openapi.json") {
				start := strings.Index(n.Data, "url: '") + len("url: '")
				end := strings.Index(n.Data[start:], "'") + start
				if start > len("url: '")-1 && end > start {
					urlStr := n.Data[start:end]
					potentialURLs = append(potentialURLs, urlStr)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	// Parse the potential URLs found in the HTML and return the first valid one
	for _, urlStr := range potentialURLs {
		swaggerURL := constructSwaggerURL(urlStr, target)
		if _, err := url.ParseRequestURI(swaggerURL); err == nil {
			fmt.Printf("Valid docs link: %s\n", swaggerURL)
			return swaggerURL, nil
		}
	}

	return "", fmt.Errorf("valid swagger.json link not found in HTML")
}

func constructSwaggerURL(urlStr, target string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil || !parsedURL.IsAbs() {
		parsedTarget, err := url.Parse(target)
		if err != nil {
			fmt.Printf("Error parsing target URL: %v\n", err)
			return ""
		}
		baseURL := fmt.Sprintf("%s://%s", parsedTarget.Scheme, parsedTarget.Host)
		if strings.HasPrefix(urlStr, "/") {
			return baseURL + urlStr
		}
		return baseURL + "/" + urlStr
	}
	return parsedURL.String()
}

func fetchSwaggerJSON(swaggerURL string) ([]byte, error) {
	resp, err := http.Get(swaggerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Swagger JSON: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Println("Error closing response body:", err)
		}
	}()

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		return nil, fmt.Errorf("invalid content type: expected application/json, got %s", contentType)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return bodyBytes, nil
}

func handleSwaggerV2(document libopenapi.Document, report *webscan.RoutesReport) error {
	report.AppType = webscan.ApiTypeSwaggerV2
	var errors []error
	var v2Model *libopenapi.DocumentModel[v2.Swagger]

	v2Model, errors = document.BuildV2Model()
	if len(errors) > 0 {
		for i := range errors {
			errMsg := fmt.Sprintf("error: %v", errors[i])
			report.Errors = append(report.Errors, errMsg)
		}
		return fmt.Errorf("cannot create v2 model from document: %d errors reported", len(errors))
	}

	model := v2Model.Model

	// Construct the base endpoint URL from the host and basePath fields
	baseEndpointURL := fmt.Sprintf("https://%s%s", model.Host, model.BasePath)
	report.BaseEndpointUrl = baseEndpointURL

	// Extract security definitions
	securityDefinitions := make(map[string]*v2.SecurityScheme)
	for pair := model.SecurityDefinitions.Definitions.Oldest(); pair != nil; pair = pair.Next() {
		securityDefinitions[pair.Key] = pair.Value
	}

	// Add security schemes to the report
	report.SecuritySchemes = convertSecurityDefinitionsV2(securityDefinitions)

	// Add app-level security requirements to the report
	securityRequirements := convertSecurityRequirementsV2(model.Security)
	if securityRequirements != nil {
		report.Security = []*webscan.SecurityRequirement{securityRequirements}
	}

	// Iterate over paths and methods to populate the report
	for pair := model.Paths.PathItems.Oldest(); pair != nil; pair = pair.Next() {
		path := pair.Key
		pathItem := pair.Value
		for opPair := pathItem.GetOperations().Oldest(); opPair != nil; opPair = opPair.Next() {
			method := opPair.Key
			operation := opPair.Value
			securityRequirements := convertSecurityRequirementsV2(operation.Security)
			route := webscan.Route{
				Path:        path,
				Method:      method,
				QueryParams: getQueryParamsV2(operation.Parameters),
				Security:    securityRequirements,
				Type:        webscan.ApiTypeSwaggerV2,
				Description: operation.Description,
			}
			report.Routes = append(report.Routes, &route)
		}
	}

	return nil
}

func handleOpenAPIV3(document libopenapi.Document, report *webscan.RoutesReport, target string) error {
	report.AppType = webscan.ApiTypeSwaggerV3
	var errors []error
	var v3Model *libopenapi.DocumentModel[v3.Document]

	v3Model, errors = document.BuildV3Model()
	if len(errors) > 0 {
		for i := range errors {
			errMsg := fmt.Sprintf("error: %v", errors[i])
			report.Errors = append(report.Errors, errMsg)
		}
		return fmt.Errorf("cannot create v3 model from document: %d errors reported", len(errors))
	}

	model := v3Model.Model

	// Construct the base endpoint URL from the servers array
	serverPath := ""
	if len(model.Servers) > 0 {
		serverPath = model.Servers[0].URL
	}
	parsedURL, err := url.Parse(target)
	if err != nil {
		errMsg := fmt.Sprintf("failed to parse target URL: %v", err)
		report.Errors = append(report.Errors, errMsg)
		return fmt.Errorf("failed to parse target URL: %v", err)
	}
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	baseURL = strings.TrimSuffix(baseURL, "/")
	report.BaseEndpointUrl = baseURL + serverPath

	// Extract security definitions
	securityDefinitions := make(map[string]*v3.SecurityScheme)
	for pair := model.Components.SecuritySchemes.Oldest(); pair != nil; pair = pair.Next() {
		securityDefinitions[pair.Key] = pair.Value
	}

	// Add security schemes to the report
	report.SecuritySchemes = convertSecurityDefinitionsV3(securityDefinitions)

	// Add app-level security requirements to the report
<<<<<<< HEAD
	securityRequirements := convertSecurityRequirementsV3(model.Security)
	if securityRequirements != nil {
		report.Security = []*webscan.SecurityRequirement{securityRequirements}
	}
=======
	report.Security = []*webscan.SecurityRequirement{convertSecurityRequirementsV3(model.Security)}
>>>>>>> origin/develop

	// Iterate over paths and methods to populate the report
	for pair := model.Paths.PathItems.Oldest(); pair != nil; pair = pair.Next() {
		path := pair.Key
		pathItem := pair.Value
		for opPair := pathItem.GetOperations().Oldest(); opPair != nil; opPair = opPair.Next() {
			method := opPair.Key
			operation := opPair.Value
			securityRequirements := convertSecurityRequirementsV3(operation.Security)
			route := webscan.Route{
				Path:        path,
				Method:      method,
				QueryParams: getQueryParamsV3(operation.Parameters),
				Security:    securityRequirements,
				Type:        webscan.ApiTypeSwaggerV3,
				Description: operation.Description,
			}
			report.Routes = append(report.Routes, &route)
		}
	}

	return nil
}

// getQueryParamsV2 extracts query parameters from the operation parameters for Swagger (OpenAPI 2.0)
func getQueryParamsV2(params []*v2.Parameter) []string {
	var queryParams []string
	for _, param := range params {
		if param.In == "query" {
			queryParams = append(queryParams, param.Name)
		}
	}
	return queryParams
}

// getQueryParamsV3 extracts query parameters from the operation parameters for OpenAPI 3.0+
func getQueryParamsV3(params []*v3.Parameter) []string {
	var queryParams []string
	for _, param := range params {
		if param.In == "query" {
			queryParams = append(queryParams, param.Name)
		}
	}
	return queryParams
}

func convertSecurityDefinitionsV2(securityDefinitions map[string]*v2.SecurityScheme) map[string]*webscan.SecurityScheme {
	schemes := make(map[string]*webscan.SecurityScheme)
	for name, scheme := range securityDefinitions {
<<<<<<< HEAD
		if scheme == nil {
			continue
		}
=======
>>>>>>> origin/develop
		webscanScheme := &webscan.SecurityScheme{
			Type:        webscan.SecuritySchemeType(scheme.Type),
			Description: &scheme.Description,
			Name:        &name,
<<<<<<< HEAD
		}

		switch scheme.Type {
		case "apiKey":
			webscanScheme.In = &scheme.In
		case "oauth2":
			webscanScheme.Flow = &scheme.Flow
			webscanScheme.AuthorizationUrl = &scheme.AuthorizationUrl
			webscanScheme.TokenUrl = &scheme.TokenUrl
			webscanScheme.Scopes = convertV2ScopesToMap(scheme.Scopes)
		}

		if webscanScheme.Type != "" {
			schemes[name] = webscanScheme
=======
>>>>>>> origin/develop
		}

		switch scheme.Type {
		case "apiKey":
			webscanScheme.In = &scheme.In
		case "oauth2":
			webscanScheme.Flow = &scheme.Flow
			webscanScheme.AuthorizationUrl = &scheme.AuthorizationUrl
			webscanScheme.TokenUrl = &scheme.TokenUrl
			webscanScheme.Scopes = convertV2ScopesToMap(scheme.Scopes)
		}

		schemes[name] = webscanScheme
	}
	return schemes
}

func convertV2ScopesToMap(scopes *v2.Scopes) map[string]string {
	if scopes == nil {
		return nil
	}
	result := make(map[string]string)
	for pair := scopes.Values.Oldest(); pair != nil; pair = pair.Next() {
		result[pair.Key] = pair.Value
<<<<<<< HEAD
	}
	return result
}

func convertSecurityDefinitionsV3(securityDefinitions map[string]*v3.SecurityScheme) map[string]*webscan.SecurityScheme {
	schemes := make(map[string]*webscan.SecurityScheme)
	for name, scheme := range securityDefinitions {
		if scheme == nil {
			continue
		}
		webscanScheme := &webscan.SecurityScheme{
			Type:        webscan.SecuritySchemeType(scheme.Type),
			Description: &scheme.Description,
			Name:        &name,
		}

		switch scheme.Type {
		case "apiKey":
			webscanScheme.In = &scheme.In
		case "http":
			webscanScheme.Scheme = &scheme.Scheme
			webscanScheme.BearerFormat = &scheme.BearerFormat
		case "oauth2":
			webscanScheme.Flows = convertOAuthFlowsV3(scheme.Flows)
		case "openIdConnect":
			webscanScheme.OpenIdConnectUrl = &scheme.OpenIdConnectUrl
		}

		if webscanScheme.Type != "" {
			schemes[name] = webscanScheme
		}
	}
	return schemes
}

=======
	}
	return result
}

func convertSecurityDefinitionsV3(securityDefinitions map[string]*v3.SecurityScheme) map[string]*webscan.SecurityScheme {
	schemes := make(map[string]*webscan.SecurityScheme)
	for name, scheme := range securityDefinitions {
		webscanScheme := &webscan.SecurityScheme{
			Type:        webscan.SecuritySchemeType(scheme.Type),
			Description: &scheme.Description,
			Name:        &name,
		}

		switch scheme.Type {
		case "apiKey":
			webscanScheme.In = &scheme.In
		case "http":
			webscanScheme.Scheme = &scheme.Scheme
			webscanScheme.BearerFormat = &scheme.BearerFormat
		case "oauth2":
			webscanScheme.Flows = convertOAuthFlowsV3(scheme.Flows)
		case "openIdConnect":
			webscanScheme.OpenIdConnectUrl = &scheme.OpenIdConnectUrl
		}

		schemes[name] = webscanScheme
	}
	return schemes
}

>>>>>>> origin/develop
func convertOAuthFlowsV3(flows *v3.OAuthFlows) *webscan.OAuthFlows {
	if flows == nil {
		return nil
	}
	return &webscan.OAuthFlows{
		Implicit:          convertOAuthFlowV3(flows.Implicit),
		Password:          convertOAuthFlowV3(flows.Password),
		ClientCredentials: convertOAuthFlowV3(flows.ClientCredentials),
		AuthorizationCode: convertOAuthFlowV3(flows.AuthorizationCode),
	}
}

func convertOAuthFlowV3(flow *v3.OAuthFlow) *webscan.OAuthFlow {
	if flow == nil {
		return nil
	}
	return &webscan.OAuthFlow{
		AuthorizationUrl: &flow.AuthorizationUrl,
		TokenUrl:         &flow.TokenUrl,
		RefreshUrl:       &flow.RefreshUrl,
		Scopes:           convertOrderedMapToMap(flow.Scopes),
	}
}

func convertOrderedMapToMap(orderedMap *orderedmap.Map[string, string]) map[string]string {
	if orderedMap == nil {
		return nil
	}
	result := make(map[string]string)
	for pair := orderedMap.Oldest(); pair != nil; pair = pair.Next() {
		result[pair.Key] = pair.Value
	}
	return result
}

func convertSecurityRequirementsV2(security []*base.SecurityRequirement) *webscan.SecurityRequirement {
	if len(security) == 0 {
		return nil
	}
	req := &webscan.SecurityRequirement{
		Schemes: make(map[string][]string),
	}
	for _, secReq := range security {
		for pair := secReq.Requirements.Oldest(); pair != nil; pair = pair.Next() {
			req.Schemes[pair.Key] = pair.Value
		}
	}
<<<<<<< HEAD
	if len(req.Schemes) == 0 {
		return nil
	}
=======
>>>>>>> origin/develop
	return req
}

func convertSecurityRequirementsV3(security []*base.SecurityRequirement) *webscan.SecurityRequirement {
	if len(security) == 0 {
		return nil
	}
	req := &webscan.SecurityRequirement{
		Schemes: make(map[string][]string),
	}
	for _, secReq := range security {
		for pair := secReq.Requirements.Oldest(); pair != nil; pair = pair.Next() {
			req.Schemes[pair.Key] = pair.Value
		}
	}
<<<<<<< HEAD
	if len(req.Schemes) == 0 {
		return nil
	}
=======
>>>>>>> origin/develop
	return req
}
