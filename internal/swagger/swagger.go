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
	"golang.org/x/net/html"
)

// PerformSwaggerScan performs a Swagger scan against a target URL and returns the report.
func PerformSwaggerScan(ctx context.Context, target string) (webscan.Report, error) {
	report := webscan.Report{Target: target}

	// Create a new context for chromedp
	ctx, cancel := chromedp.NewContext(ctx)
	defer cancel()

	// Create a timeout context
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Fetch the fully rendered HTML content
	var body string
	err := chromedp.Run(ctx,
		chromedp.Navigate(target),
		chromedp.OuterHTML("html", &body),
	)
	if err != nil {
		return report, fmt.Errorf("failed to fetch HTML: %v", err)
	}

	// Parse the HTML to find the Swagger JSON link
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return report, fmt.Errorf("failed to parse HTML: %v", err)
	}

	var swaggerURL string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, a := range n.Attr {
				if strings.Contains(a.Val, "swagger.json") {
					// Ensure the base part of the URL matches the target's base
					if strings.HasPrefix(a.Val, target[:strings.LastIndex(target, "/")+1]) {
						swaggerURL = a.Val
						fmt.Printf("Found swagger.json link: %s\n", swaggerURL)
						return
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	if swaggerURL == "" {
		return report, fmt.Errorf("swagger.json link not found in HTML")
	}

	// Construct the full URL if the found URL is relative
	if !strings.HasPrefix(swaggerURL, "http") {
		baseURL := target[:strings.LastIndex(target, "/")+1]
		swaggerURL = baseURL + swaggerURL
	}

	// Update the report with the found Swagger URL
	report.SchemaUrl = &swaggerURL

	// Fetch the Swagger JSON
	resp, err := http.Get(swaggerURL)
	if err != nil {
		return report, fmt.Errorf("failed to fetch Swagger JSON: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Println("Error closing response body:", err)
		}
	}()

	// Check if the content type is JSON
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		return report, fmt.Errorf("invalid content type: expected application/json, got %s", contentType)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return report, fmt.Errorf("failed to read response body: %v", err)
	}

	// Encode the raw body in base64 and add to the report
	report.Raw = base64.StdEncoding.EncodeToString(bodyBytes)

	// create a new document from specification bytes
	document, err := libopenapi.NewDocument(bodyBytes)
	if err != nil {
		return report, fmt.Errorf("cannot create new document: %v", err)
	}

	// Determine if the document is Swagger (OpenAPI 2.0) or OpenAPI 3.0+
	var docType map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &docType); err != nil {
		return report, fmt.Errorf("failed to unmarshal document type: %v", err)
	}

	if version, ok := docType["swagger"]; ok && version == "2.0" {
		// Handle Swagger (OpenAPI 2.0)
		report.AppType = webscan.ApiTypeSwaggerV2
		var errors []error
		var v2Model *libopenapi.DocumentModel[v2.Swagger]

		v2Model, errors = document.BuildV2Model()
		if len(errors) > 0 {
			for i := range errors {
				fmt.Printf("error: %v\n", errors[i])
			}
			return report, fmt.Errorf("cannot create v2 model from document: %d errors reported", len(errors))
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

		// Iterate over paths and methods to populate the report
		for pair := model.Paths.PathItems.Oldest(); pair != nil; pair = pair.Next() {
			path := pair.Key
			pathItem := pair.Value
			for opPair := pathItem.GetOperations().Oldest(); opPair != nil; opPair = opPair.Next() {
				method := opPair.Key
				operation := opPair.Value
				authType := getAuthTypeV2(convertSecurityRequirementsV2(operation.Security), securityDefinitions)
				route := webscan.Route{
					Path:        path,
					Method:      method,
					Queryparams: getQueryParamsV2(operation.Parameters),
					Auth:        &authType,
					Type:        webscan.ApiTypeSwaggerV2,
					Description: operation.Description,
				}
				report.Routes = append(report.Routes, &route)
			}
		}
	} else if version, ok := docType["openapi"]; ok && strings.HasPrefix(version.(string), "3.0") {
		// Handle OpenAPI 3.0+
		report.AppType = webscan.ApiTypeSwaggerV3
		var errors []error
		var v3Model *libopenapi.DocumentModel[v3.Document]

		v3Model, errors = document.BuildV3Model()
		if len(errors) > 0 {
			for i := range errors {
				fmt.Printf("error: %v\n", errors[i])
			}
			return report, fmt.Errorf("cannot create v3 model from document: %d errors reported", len(errors))
		}

		model := v3Model.Model

		// Construct the base endpoint URL from the servers array
		if len(model.Servers) > 0 {
			serverPath := model.Servers[0].URL
			parsedURL, err := url.Parse(target)
			if err != nil {
				return report, fmt.Errorf("failed to parse target URL: %v", err)
			}
			baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
			baseURL = strings.TrimSuffix(baseURL, "/")
			report.BaseEndpointUrl = baseURL + serverPath
		}

		// Extract security definitions
		securityDefinitions := make(map[string]*v3.SecurityScheme)
		for pair := model.Components.SecuritySchemes.Oldest(); pair != nil; pair = pair.Next() {
			securityDefinitions[pair.Key] = pair.Value
		}

		// Iterate over paths and methods to populate the report
		for pair := model.Paths.PathItems.Oldest(); pair != nil; pair = pair.Next() {
			path := pair.Key
			pathItem := pair.Value
			for opPair := pathItem.GetOperations().Oldest(); opPair != nil; opPair = opPair.Next() {
				method := opPair.Key
				operation := opPair.Value
				authType := getAuthTypeV3(convertSecurityRequirementsV3(operation.Security), securityDefinitions)
				route := webscan.Route{
					Path:        path,
					Method:      method,
					Queryparams: getQueryParamsV3(operation.Parameters),
					Auth:        &authType,
					Type:        webscan.ApiTypeSwaggerV3,
					Description: operation.Description,
				}
				report.Routes = append(report.Routes, &route)
			}
		}
	} else {
		return report, fmt.Errorf("unsupported OpenAPI version")
	}

	return report, nil
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

// getAuthTypeV2 determines the authentication type from the security requirements for Swagger (OpenAPI 2.0)
func getAuthTypeV2(security map[string][]string, securityDefinitions map[string]*v2.SecurityScheme) string {
	if len(security) == 0 {
		return "none"
	}
	for name := range security {
		if secDef, ok := securityDefinitions[name]; ok {
			switch secDef.Type {
			case "apiKey":
				return "apiKey"
			case "oauth2":
				return "oauth2"
			case "basic":
				return "basic"
			default:
				return "unknown"
			}
		}
	}
	return "unknown"
}

// getAuthTypeV3 determines the authentication type from the security requirements for OpenAPI 3.0+
func getAuthTypeV3(security map[string][]string, securityDefinitions map[string]*v3.SecurityScheme) string {
	if len(security) == 0 {
		return "none"
	}
	for name := range security {
		if secDef, ok := securityDefinitions[name]; ok {
			switch secDef.Type {
			case "apiKey":
				return "apiKey"
			case "oauth2":
				return "oauth2"
			case "http":
				return "http"
			default:
				return "unknown"
			}
		}
	}
	return "unknown"
}

func convertSecurityRequirementsV2(security []*base.SecurityRequirement) map[string][]string {
	securityMap := make(map[string][]string)
	for _, secReq := range security {
		for pair := secReq.Requirements.Oldest(); pair != nil; pair = pair.Next() {
			securityMap[pair.Key] = pair.Value
		}
	}
	return securityMap
}

func convertSecurityRequirementsV3(security []*base.SecurityRequirement) map[string][]string {
	securityMap := make(map[string][]string)
	for _, secReq := range security {
		for pair := secReq.Requirements.Oldest(); pair != nil; pair = pair.Next() {
			securityMap[pair.Key] = pair.Value
		}
	}
	return securityMap
}
