package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/pb33f/libopenapi"
	"github.com/pb33f/libopenapi/datamodel/high/base"
	v2 "github.com/pb33f/libopenapi/datamodel/high/v2"
)

//  TODO: support request / response schemas

// Route represents a single API route with its details.
type Route struct {
	Path        string   `json:"path"`
	QueryParams []string `json:"query_params"`
	Auth        *string  `json:"auth"`
	Method      string   `json:"method"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
}

// Report represents the report of the Swagger API enumeration.
type Report struct {
	Target string  `json:"target"`
	Routes []Route `json:"routes"`
}

// PerformSwaggerScan performs a Swagger scan against a target URL and returns the report.
func PerformSwaggerScan(ctx context.Context, target string) (Report, error) {
	report := Report{Target: target}

	// Fetch the Swagger JSON
	resp, err := http.Get(target)
	if err != nil {
		return report, fmt.Errorf("failed to fetch Swagger JSON: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return report, fmt.Errorf("failed to read response body: %v", err)
	}

	// create a new document from specification bytes
	document, err := libopenapi.NewDocument(body)
	if err != nil {
		return report, fmt.Errorf("cannot create new document: %v", err)
	}

	// define variables to capture the v2 model, or any errors thrown
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
			authType := getAuthType(convertSecurityRequirements(operation.Security), securityDefinitions)
			route := Route{
				Path:        path,
				Method:      method,
				QueryParams: getQueryParams(operation.Parameters),
				Auth:        &authType,
				Type:        "swagger",
				Description: operation.Description,
			}
			report.Routes = append(report.Routes, route)
		}
	}

	return report, nil
}

// getQueryParams extracts query parameters from the operation parameters
func getQueryParams(params []*v2.Parameter) []string {
	var queryParams []string
	for _, param := range params {
		if param.In == "query" {
			queryParams = append(queryParams, param.Name)
		}
	}
	return queryParams
}

// getAuthType determines the authentication type from the security requirements
func getAuthType(security map[string][]string, securityDefinitions map[string]*v2.SecurityScheme) string {
	if len(security) == 0 {
		return "none"
	}
	// Simplified logic to determine auth type
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

func convertSecurityRequirements(security []*base.SecurityRequirement) map[string][]string {
	securityMap := make(map[string][]string)
	for _, secReq := range security {
		for pair := secReq.Requirements.Oldest(); pair != nil; pair = pair.Next() {
			securityMap[pair.Key] = pair.Value
		}
	}
	return securityMap
}

// Temporary main function for testing
func main() {
	target := "http://petstore.swagger.io/v2/swagger.json"
	report, err := PerformSwaggerScan(context.Background(), target)
	if err != nil {
		log.Fatalf("Failed to perform Swagger scan: %v", err)
	}

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal report: %v", err)
	}

	fmt.Println(string(reportJSON))
}
