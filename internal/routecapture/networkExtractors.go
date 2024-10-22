package routecapture

import (
	"context"
	"net/url"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
	capture "github.com/Method-Security/webscan/internal/capture"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// extractNetworkRoutes fetches network requests, parses them, and populates []WebRoute.
func extractNetworkRoutes(ctx context.Context, b *capture.BrowserPageCapturer, target string, baseURLsOnly bool, captureStaticAssets bool) ([]*webscan.WebRoute, []string, []string) {
	routes := []*webscan.WebRoute{}
	urls := make(map[string]struct{})
	errors := []string{}
	log := svc1log.FromContext(ctx)

	log.Info("Initiating network events capture with browser method", svc1log.SafeParam("target", target))
	// Ensure the browser is initialized
	if b.Browser == nil {
		log.Debug("Initializing browser for network capture")
		b.InitializeBrowser()
	}

	// Set up a page with timeout context
	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	var page *rod.Page
	pageErr := rod.Try(func() {
		page = b.Browser.MustPage(target).Context(pageCtx)
	})
	if pageErr != nil {
		log.Error("Failed to create page", svc1log.SafeParam("url", target), svc1log.SafeParam("error", pageErr))
		errors = append(errors, pageErr.Error())
		return routes, setToListString(urls), errors
	}
	log.Debug("Successfully connected to page for network capture")

	// Enable network event tracking
	networkEventErr := proto.NetworkEnable{}.Call(page)
	if networkEventErr != nil {
		log.Error("Failed to enable network tracking", svc1log.SafeParam("error", networkEventErr))
		errors = append(errors, networkEventErr.Error())
		return routes, setToListString(urls), errors
	}

	// Capture network requests of type 'fetch' which are typical of API calls
	networkEvents := []*proto.NetworkRequestWillBeSent{}
	waitForNetworkEvents := page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		log.Debug("Captured network event", svc1log.SafeParam("url", e.Request.URL), svc1log.SafeParam("type", e.Type))
		// Only capture fetch requests
		if e.Type == proto.NetworkResourceTypeFetch {
			networkEvents = append(networkEvents, e)
		}
	})

	// Navigate to the page
	err := page.Navigate(target)
	if err != nil {
		log.Error("Failed to navigate to page", svc1log.SafeParam("url", target), svc1log.SafeParam("error", err))
		errors = append(errors, err.Error())
		return routes, setToListString(urls), errors
	}
	// Wait for the page to load
	err = page.WaitLoad()
	if err != nil {
		log.Debug("Failed to wait for page load", svc1log.SafeParam("url", target), svc1log.SafeParam("error", err))
		errors = append(errors, err.Error())
		// Reload the page if it can't load, possible redirect
		reloadErr := page.Reload()
		if reloadErr != nil {
			log.Error("Failed to reload page", svc1log.SafeParam("url", target), svc1log.SafeParam("error", reloadErr))
			errors = append(errors, reloadErr.Error())
			return routes, setToListString(urls), errors
		}
	}
	// Wait for network events to be captured
	waitForNetworkEvents()

	// Process network events and populate the WebRoute structure
	for _, event := range networkEvents {
		request := event.Request

		// Filter requests by base domain if required
		reqURL, err := url.Parse(request.URL)
		if err != nil {
			log.Error("Failed to parse URL", svc1log.SafeParam("url", request.URL), svc1log.SafeParam("error", err))
			continue
		}

		// Skip requests that don't match the base domain when baseURLsOnly is true
		if !isURLAllowed(target, reqURL.String(), baseURLsOnly, captureStaticAssets) {
			log.Debug("Skipping URL", svc1log.SafeParam("url", reqURL.String()), svc1log.SafeParam("target", target))
			continue
		}

		// The route URL should not have query params, those are stored in QueryParams
		urlNoQuery, err := urlRemoveQueryParams(request.URL)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// Get the path from the full URL
		parsedURL, err := url.Parse(urlNoQuery)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// Build WebRoute object
		webRoute := &webscan.WebRoute{
			Url:    urlNoQuery,
			Path:   &parsedURL.Path,
			Method: webscan.HttpMethod(request.Method).Ptr(),
		}

		// Capture query parameters
		webRoute.QueryParams = parseQueryParams(reqURL)

		// Capture body parameters (if any)
		if request.HasPostData {
			webRoute.BodyParams, err = parseBodyParams(request.PostData)
		}
		if err != nil {
			errors = append(errors, err.Error())
		}

		// Add the WebRoute to the list
		routes = append(routes, webRoute)
	}

	return mergeWebRoutes(routes), setToListString(urls), errors
}
