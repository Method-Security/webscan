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
	parsedURL, err := url.Parse("https://example.com/api/check?t=1790611384013&time=1790611384&timestamp=1790611384013000&epoch=1790611384013000000&isJapan=false")
	if err != nil {
		t.Fatalf("failed to parse test URL: %v", err)
	}

	params := discoverroute.ParseQueryParams(parsedURL)
	for _, name := range []string{"t", "time", "timestamp", "epoch"} {
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
	parsedURL, err := url.Parse("https://example.com/items?id=1042&build=20260806&largeId=179061138401&orderId=1790611384&snowflakeId=1790611384013000000")
	if err != nil {
		t.Fatalf("failed to parse test URL: %v", err)
	}

	params := discoverroute.ParseQueryParams(parsedURL)
	for name, value := range map[string]string{
		"id":          "1042",
		"build":       "20260806",
		"largeId":     "179061138401",
		"orderId":     "1790611384",
		"snowflakeId": "1790611384013000000",
	} {
		param := queryParamByName(params, name)
		if param == nil || len(param.ExampleValues) != 1 || param.ExampleValues[0] != value {
			t.Errorf("expected %q example %q to remain, got %v", name, value, param)
		}
	}
}
