package routecapture

import (
	"fmt"
	"net/url"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go"
	"github.com/PuerkitoBio/goquery"
)

// extractFormRoutes extracts WebRoutes from form elements in the HTML document
// It returns a slice of WebRoutes, a slice of URLs and a slice of errors
// WebRoutes are merged to only return unique routes
func extractFormRoutes(doc *goquery.Document, baseURL string, baseURLsOnly bool) ([]*webscan.WebRoute, []string, []string) {
	routes := []*webscan.WebRoute{}
	urls := make(map[string]struct{})
	errors := []string{}

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		fmt.Println("Form found")
		route := webscan.WebRoute{}

		// Extract action attribute
		action, exists := s.Attr("action")
		if !exists || action == "" {
			action = "" // Default action is current page
		}

		// Resolve the action URL relative to the base URL
		fullURL := resolveURL(baseURL, action)

		// Check if the URL is allowed
		if !isURLAllowed(baseURL, fullURL, baseURLsOnly) {
			return
		}

		// The route URL should not have query params, those are stored in QueryParams
		urlNoQuery, err := urlRemoveQueryParams(fullURL)
		if err != nil {
			errors = append(errors, err.Error())
			return
		}
		route.Url = urlNoQuery
		urls[urlNoQuery] = struct{}{}

		// Extract method attribute
		method, exists := s.Attr("method")
		if !exists || method == "" {
			method = "GET"
		} else {
			method = strings.ToUpper(method)
		}
		route.Method = webscan.HttpMethod(method).Ptr()

		// Get the path from the full URL and set it
		parsedURL, err := url.Parse(fullURL)
		if err == nil {
			route.Path = &parsedURL.Path
		}

		// Collect input names
		var queryParams []*webscan.QueryParams
		var bodyParams []*webscan.BodyParams
		s.Find("input[name], select[name], textarea[name]").Each(func(_ int, input *goquery.Selection) {
			name, _ := input.Attr("name")
			if name != "" {
				if method == "POST" || method == "PUT" || method == "PATCH" {
					// For POST, PUT, PATCH methods, add to BodyParams
					param := &webscan.BodyParams{Name: name}
					bodyParams = append(bodyParams, param)
				} else {
					// For GET and other methods, add to QueryParams
					param := &webscan.QueryParams{Name: name}
					queryParams = append(queryParams, param)
				}
			}
		})

		if len(queryParams) > 0 {
			route.QueryParams = queryParams
		}
		if len(bodyParams) > 0 {
			route.BodyParams = bodyParams
		}

		routes = append(routes, &route)
	})

	return mergeWebRoutes(routes), setToListString(urls), []string{}
}

func extractAnchorRoutes(doc *goquery.Document, baseURL string, baseURLsOnly bool) ([]*webscan.WebRoute, []string, []string) {
	routes := []*webscan.WebRoute{}
	urls := make(map[string]struct{})
	errors := []string{}

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && href != "" {
			fullURL := resolveURL(baseURL, href)

			// The route URL should not have query params, those are stored in QueryParams
			urlNoQuery, err := urlRemoveQueryParams(fullURL)
			if err != nil {
				errors = append(errors, err.Error())
				return
			}

			// Check if the URL is allowed
			if !isURLAllowed(baseURL, fullURL, baseURLsOnly) {
				return
			}
			urls[urlNoQuery] = struct{}{}

			// Get the path from the full URL
			parsedURL, err := url.Parse(urlNoQuery)
			if err != nil {
				errors = append(errors, err.Error())
				return
			}

			route := &webscan.WebRoute{
				Url:    urlNoQuery,
				Path:   &parsedURL.Path,
				Method: webscan.HttpMethodGet.Ptr(), // Anchor links are accessed via GET
			}

			routes = append(routes, route)
		}
	})

	return mergeWebRoutes(routes), setToListString(urls), errors
}

func extractLinkRoutes(doc *goquery.Document, baseURL string, baseURLsOnly bool) ([]*webscan.WebRoute, []string, []string) {
	routes := []*webscan.WebRoute{}
	urls := make(map[string]struct{})
	errors := []string{}

	doc.Find("link[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && href != "" {
			fullURL := resolveURL(baseURL, href)

			// The route URL should not have query params, those are stored in QueryParams
			urlNoQuery, err := urlRemoveQueryParams(fullURL)
			if err != nil {
				errors = append(errors, err.Error())
				return
			}

			// Check if the URL is allowed
			if !isURLAllowed(baseURL, fullURL, baseURLsOnly) {
				return
			}

			urls[urlNoQuery] = struct{}{}

			// Get the path from the full URL
			parsedURL, err := url.Parse(urlNoQuery)
			if err != nil {
				errors = append(errors, err.Error())
				return
			}

			route := &webscan.WebRoute{
				Url:    urlNoQuery,
				Path:   &parsedURL.Path,
				Method: webscan.HttpMethodGet.Ptr(), // Link elements are accessed via GET
			}

			routes = append(routes, route)
		}
	})

	return mergeWebRoutes(routes), setToListString(urls), errors
}
