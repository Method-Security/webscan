package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// Route represents a single API route with its details.
type Route struct {
	Path        string   `json:"path"`
	QueryParams []string `json:"query_params"`
	Auth        *string  `json:"auth"`
	Method      string   `json:"method"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
}

// GraphQlReport represents the report of the GraphQL API enumeration.
type GraphQlReport struct {
	Target string  `json:"target"`
	Routes []Route `json:"routes"`
}

// GraphQLSchema represents the structure of the GraphQL schema response.
type GraphQLSchema struct {
	Data struct {
		Schema struct {
			Types []struct {
				Name        string `json:"name"`
				Kind        string `json:"kind"`
				Description string `json:"description"`
				Fields      []struct {
					Name string `json:"name"`
				} `json:"fields"`
			} `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
}

// PerformGraphQLScan performs a GraphQL scan against a target URL and returns the report.
func PerformGraphQLScan(ctx context.Context, target string) (GraphQlReport, error) {
	report := GraphQlReport{Target: target}

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

	var schema GraphQLSchema
	if err := json.Unmarshal(body, &schema); err != nil {
		return report, fmt.Errorf("failed to unmarshal schema: %v", err)
	}

	// Create a map to store fields for each type, using lowercase keys for case-insensitivity
	typeFields := make(map[string][]string)
	for _, t := range schema.Data.Schema.Types {
		if t.Kind == "OBJECT" {
			for _, field := range t.Fields {
				typeFields[strings.ToLower(t.Name)] = append(typeFields[strings.ToLower(t.Name)], field.Name)
			}
		}
	}

	// Iterate over types and fields to populate the report
	for _, t := range schema.Data.Schema.Types {
		if t.Kind == "OBJECT" && (t.Name == "Query" || t.Name == "Mutation" || t.Name == "Subscription") {
			for _, field := range t.Fields {
				route := Route{
					Path:        fmt.Sprintf("/%s/%s", t.Name, field.Name),
					Method:      "POST",
					Auth:        nil,
					QueryParams: typeFields[strings.ToLower(field.Name)],
					Type:        "graphql",
					Description: t.Description,
				}
				report.Routes = append(report.Routes, route)
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
