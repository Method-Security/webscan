package routecapture

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go"
)

// setToListString converts a set of strings to a list of strings.
func setToListString(set map[string]struct{}) []string {
	list := make([]string, 0, len(set))
	for key := range set {
		list = append(list, key)
	}
	return list
}

// addListToSetString adds elements from a list of strings to a set of strings.
func addListToSetString(set map[string]struct{}, list []string) map[string]struct{} {
	for _, item := range list {
		set[item] = struct{}{}
	}
	return set
}

// mergeWebRoutes merges WebRoutes, retaining only unique routes
// unique routes are defined by the combination of method and URL
func mergeWebRoutes(routes []*webscan.WebRoute) []*webscan.WebRoute {
	routeMap := make(map[string]*webscan.WebRoute)

	for _, route := range routes {
		// Create a unique key based on method and URL
		method := "GET"
		if route.Method != nil {
			method = string(*route.Method)
		}
		key := method + ":" + route.Url

		if existingRoute, exists := routeMap[key]; exists {
			// Merge QueryParams
			existingRoute.QueryParams = mergeQueryParams(existingRoute.QueryParams, route.QueryParams)
			// Merge BodyParams
			existingRoute.BodyParams = mergeBodyParams(existingRoute.BodyParams, route.BodyParams)
		} else {
			// Add new route to the map
			// Create a copy to avoid modifying the original
			newRoute := route
			routeMap[key] = newRoute
		}
	}

	// Convert map back to slice
	var mergedRoutes []*webscan.WebRoute
	for _, route := range routeMap {
		mergedRoutes = append(mergedRoutes, route)
	}

	return mergedRoutes
}

// Helper function to merge QueryParams only retaining those that are unique
// When the same param name is encountered, the example values are merged
func mergeQueryParams(params1 []*webscan.QueryParams, params2 []*webscan.QueryParams) []*webscan.QueryParams {
	// If either is nil return the other
	if params1 == nil && params2 == nil {
		return nil
	} else if params1 == nil {
		return params2
	} else if params2 == nil {
		return params1
	}

	// Merge
	paramMap := make(map[string]*webscan.QueryParams)
	for _, param := range params1 {
		paramMap[param.Name] = param
	}
	for _, param := range params2 {
		if _, exists := paramMap[param.Name]; !exists {
			existingParam := paramMap[param.Name]
			if existingParam.ExampleValues != nil && param.ExampleValues != nil {
				existingParam.ExampleValues = append(existingParam.ExampleValues, param.ExampleValues...)
			} else if param.ExampleValues != nil {
				existingParam.ExampleValues = param.ExampleValues
			} // else existingParam.ExampleValues is already set
			paramMap[param.Name] = existingParam
		}
	}

	// Convert map back to slice
	var mergedParams []*webscan.QueryParams
	for _, param := range paramMap {
		mergedParams = append(mergedParams, param)
	}
	return mergedParams
}

// Helper function to merge BodyParams only retaining those that are unique
// When the same param name is encountered, the example values are merged
func mergeBodyParams(params1 []*webscan.BodyParams, params2 []*webscan.BodyParams) []*webscan.BodyParams {
	// If either is nil return the other
	if params1 == nil && params2 == nil {
		return nil
	} else if params1 == nil {
		return params2
	} else if params2 == nil {
		return params1
	}

	// Merge
	paramMap := make(map[string]*webscan.BodyParams)
	for _, param := range params1 {
		paramMap[param.Name] = param
	}
	for _, param := range params2 {
		if _, exists := paramMap[param.Name]; !exists {
			existingParam := paramMap[param.Name]
			if existingParam.ExampleValues != nil && param.ExampleValues != nil {
				existingParam.ExampleValues = append(existingParam.ExampleValues, param.ExampleValues...)
			} else if param.ExampleValues != nil {
				existingParam.ExampleValues = param.ExampleValues
			} // else existingParam.ExampleValues is already set
			paramMap[param.Name] = existingParam
		}
	}

	// Convert map back to slice
	var mergedParams []*webscan.BodyParams
	for _, param := range paramMap {
		mergedParams = append(mergedParams, param)
	}
	return mergedParams
}

// Helper to parse query parameters from the URL
func parseQueryParams(reqURL *url.URL) []*webscan.QueryParams {
	var queryParams []*webscan.QueryParams
	for key, values := range reqURL.Query() {
		queryParams = append(queryParams, &webscan.QueryParams{
			Name:          key,
			ExampleValues: values,
		})
	}
	return queryParams
}

// Helper to parse body parameters
func parseBodyParams(postData string) ([]*webscan.BodyParams, error) {
	var bodyParams []*webscan.BodyParams

	// For simplicity, assume the body is JSON or form-urlencoded
	if strings.HasPrefix(postData, "{") {
		// Try to parse JSON
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(postData), &jsonData); err == nil {
			for key, value := range jsonData {
				// Stringify the value to ensure it's a string
				valueStr, err := json.Marshal(value)
				if err == nil {
					bodyParams = append(bodyParams, &webscan.BodyParams{
						Name:          key,
						ExampleValues: []string{string(valueStr)}, // Store as a string
					})
				} else {
					return bodyParams, fmt.Errorf("failed to stringify json value: %v", err)
				}
			}
		} else {
			return bodyParams, fmt.Errorf("failed to parse json: %v", err)
		}
	} else {
		// Parse form-urlencoded data
		formData, err := url.ParseQuery(postData)
		if err == nil {
			for key, values := range formData {
				bodyParams = append(bodyParams, &webscan.BodyParams{
					Name:          key,
					ExampleValues: values,
				})
			}
		} else {
			return bodyParams, fmt.Errorf("failed to parse form-urlencoded data: %v", err)
		}
	}

	return bodyParams, nil
}

// Helper function to resolve relative URLs
func resolveURL(base, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	// Return with trailing slash removed
	return strings.TrimRight(baseURL.ResolveReference(refURL).String(), "/")
}

// Helper function to remove query parameters from a URL
func urlRemoveQueryParams(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	parsedURL.RawQuery = ""
	return parsedURL.String(), nil
}

// Function to check if a URL is allowed based on baseUrlsOnly and base domain
// This only checks the first subdomain only of the baseURL as a condition for match
// Web routes often get redirected to www.* or other subdomains, so we only check the base domain
// baseURL should be the original URL sent to the CLI, targetURL is the URL discovered that needs checking
func isURLAllowed(baseURL string, targetURL string, baseUrlsOnly bool) bool {
	if !baseUrlsOnly {
		return true
	}

	baseDomain := extractDomain(baseURL, 2)
	targetDomain := extractDomain(targetURL, 0)

	// Check if targetDomain is the same as baseDomain or a subdomain
	return isSubdomain(baseDomain, targetDomain)
}

// Helper function to extract the domain from a URL with an optional maxDomainLevel parameter
// maxDomainLevel specifies the number of domain levels to include in the extracted domain
// e.g. maxDomainLevel=2 would extract "example.com" from "www.sub.example.com"
// maxDomainLevel=0 would extract the full domain
func extractDomain(rawURL string, maxDomainLevel int) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	domain := u.Hostname()

	if maxDomainLevel > 0 {
		parts := strings.Split(domain, ".")
		if len(parts) > maxDomainLevel {
			domain = strings.Join(parts[len(parts)-maxDomainLevel:], ".")
		}
	}

	return domain
}

// Helper function to check if sub is a subdomain of base
func isSubdomain(base string, sub string) bool {
	if base == "" || sub == "" {
		return false
	}
	return sub == base || strings.HasSuffix(sub, "."+base)
}

// Helper function to check if a URL is absolute
func isAbsoluteURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "//")
}
