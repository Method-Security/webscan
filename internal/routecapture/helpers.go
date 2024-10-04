package routecapture

import (
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

// mergeWebRoutes merges two slices of WebRoutes into a single slice, retaining only unique routes
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
func mergeQueryParams(params1, params2 []*webscan.QueryParams) []*webscan.QueryParams {
	paramMap := make(map[string]*webscan.QueryParams)
	for _, param := range params1 {
		paramMap[param.Name] = param
	}
	for _, param := range params2 {
		if _, exists := paramMap[param.Name]; !exists {
			paramMap[param.Name] = param
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
func mergeBodyParams(params1, params2 []*webscan.BodyParams) []*webscan.BodyParams {
	paramMap := make(map[string]*webscan.BodyParams)
	for _, param := range params1 {
		paramMap[param.Name] = param
	}
	for _, param := range params2 {
		if _, exists := paramMap[param.Name]; !exists {
			paramMap[param.Name] = param
		}
	}
	// Convert map back to slice
	var mergedParams []*webscan.BodyParams
	for _, param := range paramMap {
		mergedParams = append(mergedParams, param)
	}
	return mergedParams
}

// Function to check if a URL is allowed based on baseUrlsOnly and base domain
func isURLAllowed(baseURL string, targetURL string, baseUrlsOnly bool) bool {
	if !baseUrlsOnly {
		return true
	}

	baseDomain := extractDomain(baseURL)
	targetDomain := extractDomain(targetURL)

	// Check if targetDomain is the same as baseDomain or a subdomain
	return isSubdomain(baseDomain, targetDomain)
}

// Helper function to extract the domain from a URL
func extractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Helper function to check if sub is a subdomain of base
func isSubdomain(base, sub string) bool {
	if base == "" || sub == "" {
		return false
	}
	return sub == base || strings.HasSuffix(sub, "."+base)
}

// Helper function to check if a URL is absolute
func isAbsoluteURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "//")
}
