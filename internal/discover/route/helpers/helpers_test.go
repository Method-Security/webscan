package discoverroute_test

import (
	"net/url"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
	discoverroute "github.com/Method-Security/webscan/internal/discover/route/helpers"
)

func queryParamByName(params []*discover.RouteQueryParam, name string) *discover.RouteQueryParam {
	for _, param := range params {
		if param.Name == name {
			return param
		}
	}
	return nil
}

func routeAt(path string) *discover.RouteDetails {
	return &discover.RouteDetails{
		BaseUrl: "https://example.com",
		Path:    path,
		Method:  common.HttpMethodGet,
	}
}

func TestMergeWebRoutesKeepsDerivationProvenance(t *testing.T) {
	// A found-location tag arriving first must not displace how the route was derived.
	found := routeAt("/documents/new")
	foundEvidence := "CONST:X"
	found.Evidence = &foundEvidence
	declared := routeAt("/documents/new")
	declaredEvidence := discoverroute.DeclaredRouteEvidence
	declared.Evidence = &declaredEvidence

	merged := discoverroute.MergeWebRoutes([]*discover.RouteDetails{found, declared})

	if len(merged) != 1 {
		t.Fatalf("expected one merged route, got %d", len(merged))
	}
	if merged[0].Evidence == nil || *merged[0].Evidence != discoverroute.DeclaredRouteEvidence {
		t.Errorf("evidence = %v, want %q", merged[0].Evidence, discoverroute.DeclaredRouteEvidence)
	}
}

func TestMergeWebRoutesRanksDeclarationAboveInterpolation(t *testing.T) {
	// Declared routes are collected first, so order alone must not decide the surviving tag.
	tagged := func(evidence string) *discover.RouteDetails {
		route := routeAt("/rest/basket/{basketId}")
		route.Evidence = &evidence
		return route
	}
	for _, order := range [][]*discover.RouteDetails{
		{tagged(discoverroute.DeclaredRouteEvidence), tagged(discoverroute.InterpolatedRouteEvidence)},
		{tagged(discoverroute.InterpolatedRouteEvidence), tagged(discoverroute.DeclaredRouteEvidence)},
	} {
		merged := discoverroute.MergeWebRoutes(order)
		if len(merged) != 1 || *merged[0].Evidence != discoverroute.DeclaredRouteEvidence {
			t.Errorf("evidence = %v, want %q", merged[0].Evidence, discoverroute.DeclaredRouteEvidence)
		}
	}
}

func TestMergePathParamsUnionsExampleValues(t *testing.T) {
	merged := discoverroute.MergePathParams(
		[]*discover.RoutePathParam{{Name: "id", ExampleValues: []string{"1042"}}},
		[]*discover.RoutePathParam{{Name: "id", ExampleValues: []string{"1042", "3517"}}},
	)

	if len(merged) != 1 {
		t.Fatalf("expected one merged param, got %d", len(merged))
	}
	if len(merged[0].ExampleValues) != 2 {
		t.Errorf("expected deduplicated union of examples, got %v", merged[0].ExampleValues)
	}
}

func TestParseQueryParamsOmitsUnixTimestampExamples(t *testing.T) {
	parsedURL, err := url.Parse("https://www.blackstone.com/wp-json/blackstone/v1/bxpwsregion/check?t=1790611384013&seconds=1790611384&micros=1790611384013000&nanos=1790611384013000000&isJapan=false")
	if err != nil {
		t.Fatalf("failed to parse test URL: %v", err)
	}

	params := discoverroute.ParseQueryParams(parsedURL)
	for _, name := range []string{"t", "seconds", "micros", "nanos"} {
		param := queryParamByName(params, name)
		if param == nil {
			t.Fatalf("expected %q query param, got %v", name, params)
		}
		if len(param.ExampleValues) != 0 {
			t.Errorf("expected %q timestamp example to be omitted, got %v", name, param.ExampleValues)
		}
	}

	isJapan := queryParamByName(params, "isJapan")
	if isJapan == nil || len(isJapan.ExampleValues) != 1 || isJapan.ExampleValues[0] != "false" {
		t.Errorf("expected stable query example to remain, got %v", isJapan)
	}
}

func TestParseQueryParamsKeepsNonTimestampNumbers(t *testing.T) {
	parsedURL, err := url.Parse("https://example.com/items?id=1042&build=20260806&largeId=179061138401")
	if err != nil {
		t.Fatalf("failed to parse test URL: %v", err)
	}

	params := discoverroute.ParseQueryParams(parsedURL)
	for name, value := range map[string]string{
		"id":      "1042",
		"build":   "20260806",
		"largeId": "179061138401",
	} {
		param := queryParamByName(params, name)
		if param == nil || len(param.ExampleValues) != 1 || param.ExampleValues[0] != value {
			t.Errorf("expected %q example %q to remain, got %v", name, value, param)
		}
	}
}

func TestParseQueryParamsOmitsTransientNamedExamples(t *testing.T) {
	parsedURL, err := url.Parse("https://example.com/items?" +
		"nonce=n1&_wpnonce=n2&csrfToken=n3&authenticity_token=n4&" +
		"requestId=r1&traceId=r2&correlationId=r3&" +
		"X-Amz-Signature=s1&X-Amz-Credential=s2&X-Amz-Date=s3&Expires=s4&Signature=s5&" +
		"_=c1&cb=c2&cacheBust=c3&cachebuster=c4&ts=c5&timestamp=c6&" +
		"documentId=doc-123&accessToken=keep-me")
	if err != nil {
		t.Fatalf("failed to parse test URL: %v", err)
	}

	params := discoverroute.ParseQueryParams(parsedURL)
	for _, name := range []string{
		"nonce",
		"_wpnonce",
		"csrfToken",
		"authenticity_token",
		"requestId",
		"traceId",
		"correlationId",
		"X-Amz-Signature",
		"X-Amz-Credential",
		"X-Amz-Date",
		"Expires",
		"Signature",
		"_",
		"cb",
		"cacheBust",
		"cachebuster",
		"ts",
		"timestamp",
	} {
		param := queryParamByName(params, name)
		if param == nil {
			t.Fatalf("expected %q query param, got %v", name, params)
		}
		if len(param.ExampleValues) != 0 {
			t.Errorf("expected %q transient example to be omitted, got %v", name, param.ExampleValues)
		}
	}

	for name, value := range map[string]string{
		"documentId":  "doc-123",
		"accessToken": "keep-me",
	} {
		param := queryParamByName(params, name)
		if param == nil || len(param.ExampleValues) != 1 || param.ExampleValues[0] != value {
			t.Errorf("expected %q example %q to remain, got %v", name, value, param)
		}
	}
}
