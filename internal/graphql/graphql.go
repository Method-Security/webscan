package graphql

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go"
)

// PerformGraphQLScan performs a GraphQL scan against a target URL and returns the report.
func PerformGraphQLScan(ctx context.Context, target string) (webscan.Report, error) {
	report := webscan.Report{Target: target, AppType: webscan.ApiTypeGraphQl}

	basePath, baseEndpointURL := extractBasePathAndEndpoint(target)
	report.BaseEndpointUrl = baseEndpointURL

	addTopLevelRoute(&report, basePath)

	body, err := fetchGraphQLSchema(target)
	if err != nil {
		return report, err
	}

	report.Raw = base64.StdEncoding.EncodeToString(body)

	var schema webscan.GraphQlSchema
	if err := json.Unmarshal(body, &schema); err != nil {
		return report, fmt.Errorf("failed to unmarshal schema: %v", err)
	}

	typeFields := extractTypeFields(schema)

	populateReportWithQueries(&report, schema, typeFields)

	return report, nil
}

func extractBasePathAndEndpoint(target string) (string, string) {
	urlParts := strings.Split(target, "/")
	basePath := "/"
	if len(urlParts) > 3 {
		basePath = "/" + strings.Join(urlParts[3:], "/")
		return basePath, strings.Join(urlParts[:3], "/")
	}
	return basePath, strings.Join(urlParts, "/")
}

func addTopLevelRoute(report *webscan.Report, basePath string) {
	baseRoute := webscan.Route{
		Path:        basePath,
		Queryparams: nil,
		Auth:        nil,
		Method:      "POST",
		Type:        webscan.ApiTypeGraphQl,
		Description: "Top-level GraphQL route",
	}
	report.Routes = append(report.Routes, &baseRoute)
}

func fetchGraphQLSchema(target string) ([]byte, error) {
	query := `{"query":"{ __schema { types { name kind description fields { name } } } }"}`
	resp, err := http.Post(target, "application/json", bytes.NewBuffer([]byte(query)))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GraphQL schema: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Println("Error closing response body:", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	return body, nil
}

func extractTypeFields(schema webscan.GraphQlSchema) map[string][]string {
	typeFields := make(map[string][]string)
	for _, t := range schema.Data.Schema.Types {
		if t.Kind == "OBJECT" {
			for _, field := range t.Fields {
				typeFields[strings.ToLower(t.Name)] = append(typeFields[strings.ToLower(t.Name)], field.Name)
			}
		}
	}
	return typeFields
}

func populateReportWithQueries(report *webscan.Report, schema webscan.GraphQlSchema, typeFields map[string][]string) {
	for _, t := range schema.Data.Schema.Types {
		if t.Kind == "OBJECT" && (t.Name == "Query" || t.Name == "Mutation" || t.Name == "Subscription") {
			for _, field := range t.Fields {
				query := webscan.GraphQlQuery{
					Type:   field.Name,
					Fields: typeFields[strings.ToLower(field.Name)],
				}
				report.Queries = append(report.Queries, &query)
			}
		}
	}
}
