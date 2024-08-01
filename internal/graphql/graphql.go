package main

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
func PerformGraphQLScan(ctx context.Context, target string) (webscan.GraphQlReport, error) {
	report := webscan.GraphQlReport{Target: target}

	// Extract the path from the target URL
	urlParts := strings.Split(target, "/")
	basePath := "/"
	if len(urlParts) > 3 {
		basePath = "/" + strings.Join(urlParts[3:], "/")
	}

	// Add top-level GraphQL route
	baseRoute := webscan.Route{
		Path:        basePath,
		Queryparams: nil,
		Auth:        nil,
		Method:      "POST",
		Type:        "graphql",
		Description: "Top-level GraphQL route",
	}
	report.Routes = append(report.Routes, &baseRoute)

	// GraphQL introspection query
	query := `{"query":"{ __schema { types { name kind description fields { name } } } }"}`
	resp, err := http.Post(target, "application/json", bytes.NewBuffer([]byte(query)))
	if err != nil {
		return report, fmt.Errorf("failed to fetch GraphQL schema: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return report, fmt.Errorf("failed to read response body: %v", err)
	}

	report.Raw = base64.StdEncoding.EncodeToString(body)

	var schema webscan.GraphQlSchema
	if err := json.Unmarshal(body, &schema); err != nil {
		return report, fmt.Errorf("failed to unmarshal schema: %v", err)
	}

	// Create a map to store fields for each type
	typeFields := make(map[string][]string)
	for _, t := range schema.Data.Schema.Types {
		if t.Kind == "OBJECT" {
			for _, field := range t.Fields {
				typeFields[strings.ToLower(t.Name)] = append(typeFields[strings.ToLower(t.Name)], field.Name)
			}
		}
	}

	// Iterate over types and fields to populate the report with GraphQL-specific queries
	for _, t := range schema.Data.Schema.Types {
		if t.Kind == "OBJECT" && (t.Name == "Query" || t.Name == "Mutation" || t.Name == "Subscription") {
			for _, field := range t.Fields {
				query := webscan.GraphQlQuery{
					Type:   field.Name,
					Fields: typeFields[strings.ToLower(field.Name)],
				}
				report.Queries = append(report.Queries, &query)
				log.Printf("Added query: %s with fields: %v", query.Type, query.Fields)
			}
		}
	}

	return report, nil
}

// Temporary main function for testing
func main() {
	target := "https://countries.trevorblades.com/"
	report, err := PerformGraphQLScan(context.Background(), target)
	if err != nil {
		log.Fatalf("Failed to perform GraphQL scan: %v", err)
	}

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal report: %v", err)
	}

	fmt.Println(string(reportJSON))
}
