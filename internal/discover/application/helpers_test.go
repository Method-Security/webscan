package application

import (
	"testing"

	"github.com/Method-Security/webscan/generated/go/discover"
)

func TestGetTemplatePathsLoadBalancer(t *testing.T) {
	resourceType := &discover.ApplicationResourceConfigType{
		ApplicationResourceType: discover.ApplicationResourceTypeLoadBalancer,
	}

	paths, err := getTemplatePaths(resourceType)
	if err != nil {
		t.Fatalf("getTemplatePaths returned error: %v", err)
	}
	if len(paths) != 1 || paths[0] != "discover/application/loadbalancer" {
		t.Fatalf("getTemplatePaths = %v, want [discover/application/loadbalancer]", paths)
	}
}

func TestApplicationResourceTypeLoadBalancer(t *testing.T) {
	resourceType, err := discover.NewApplicationResourceTypeFromString("LOAD_BALANCER")
	if err != nil {
		t.Fatalf("NewApplicationResourceTypeFromString returned error: %v", err)
	}
	if resourceType != discover.ApplicationResourceTypeLoadBalancer {
		t.Fatalf("resourceType = %q, want %q", resourceType, discover.ApplicationResourceTypeLoadBalancer)
	}
}

func TestGetTemplatePathsContentDeliveryNetwork(t *testing.T) {
	resourceType := &discover.ApplicationResourceConfigType{
		ApplicationResourceType: discover.ApplicationResourceTypeContentDeliveryNetwork,
	}

	paths, err := getTemplatePaths(resourceType)
	if err != nil {
		t.Fatalf("getTemplatePaths returned error: %v", err)
	}
	if len(paths) != 1 || paths[0] != "discover/application/contentdeliverynetwork" {
		t.Fatalf("getTemplatePaths = %v, want [discover/application/contentdeliverynetwork]", paths)
	}
}

func TestApplicationResourceTypeContentDeliveryNetwork(t *testing.T) {
	resourceType, err := discover.NewApplicationResourceTypeFromString("CONTENT_DELIVERY_NETWORK")
	if err != nil {
		t.Fatalf("NewApplicationResourceTypeFromString returned error: %v", err)
	}
	if resourceType != discover.ApplicationResourceTypeContentDeliveryNetwork {
		t.Fatalf("resourceType = %q, want %q", resourceType, discover.ApplicationResourceTypeContentDeliveryNetwork)
	}
}
