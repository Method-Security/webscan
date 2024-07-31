package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/protobuf/proto"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
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

// Report represents the report of the gRPC API enumeration.
type Report struct {
	Target string  `json:"target"`
	Routes []Route `json:"routes"`
}

// PerformGRPCScan performs a gRPC scan against a target URL and returns the report.
func PerformGRPCScan(ctx context.Context, target string) (Report, error) {
	report := Report{Target: target}

	// Connect to the gRPC server
	log.Printf("Connecting to gRPC server at %s", target)
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock(), grpc.WithTimeout(60*time.Second))
	if err != nil {
		return report, fmt.Errorf("failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	// Create a new reflection client
	log.Println("Creating reflection client")
	client := grpc_reflection_v1alpha.NewServerReflectionClient(conn)
	stream, err := client.ServerReflectionInfo(ctx)
	if err != nil {
		return report, fmt.Errorf("failed to create reflection client: %v", err)
	}

	// Request the list of services
	log.Println("Requesting list of services")
	if err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{
			ListServices: "*",
		},
	}); err != nil {
		return report, fmt.Errorf("failed to request list of services: %v", err)
	}

	// Receive the list of services
	log.Println("Receiving list of services")
	resp, err := stream.Recv()
	if err != nil {
		return report, fmt.Errorf("failed to receive list of services: %v", err)
	}

	services := resp.GetListServicesResponse().Service
	log.Printf("Found %d services", len(services))

	// Iterate over services to populate the report
	for _, service := range services {
		serviceName := service.Name
		log.Printf("Processing service: %s", serviceName)

		// Request the file descriptor for the service
		if err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
			MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_FileContainingSymbol{
				FileContainingSymbol: serviceName,
			},
		}); err != nil {
			return report, fmt.Errorf("failed to request file descriptor for service %s: %v", serviceName, err)
		}

		// Receive the file descriptor
		resp, err := stream.Recv()
		if err != nil {
			return report, fmt.Errorf("failed to receive file descriptor for service %s: %v", serviceName, err)
		}

		fileDescriptor := resp.GetFileDescriptorResponse().FileDescriptorProto
		log.Printf("Received %d file descriptors for service %s", len(fileDescriptor), serviceName)

		// Extract methods and their input types from the file descriptor
		for _, fd := range fileDescriptor {
			var fileDesc descriptorpb.FileDescriptorProto
			if err := proto.Unmarshal(fd, &fileDesc); err != nil {
				return report, fmt.Errorf("failed to unmarshal file descriptor: %v", err)
			}

			for _, service := range fileDesc.Service {
				for _, method := range service.Method {
					queryParams := extractFields(&fileDesc, method.GetInputType())
					route := Route{
						Path:        fmt.Sprintf("/%s/%s", service.GetName(), method.GetName()),
						Method:      "POST",
						Auth:        nil,
						QueryParams: queryParams,
						Type:        "grpc",
						Description: method.GetName(),
					}
					report.Routes = append(report.Routes, route)
					log.Printf("Added route: %s with query params: %v", route.Path, queryParams)
				}
			}
		}
	}

	return report, nil
}

// extractFields extracts the fields of a given message type from the file descriptor.
func extractFields(fileDesc *descriptorpb.FileDescriptorProto, messageType string) []string {
	var fields []string
	for _, msg := range fileDesc.MessageType {
		if fmt.Sprintf(".%s.%s", fileDesc.GetPackage(), msg.GetName()) == messageType {
			for _, field := range msg.Field {
				fields = append(fields, field.GetName())
			}
			break
		}
	}
	return fields
}

// Temporary main function for testing
func main() {
	target := "grpc.postman-echo.com:443"
	fmt.Printf("Starting gRPC scan for target: %s\n", target)
	report, err := PerformGRPCScan(context.Background(), target)
	if err != nil {
		log.Fatalf("Failed to perform gRPC scan: %v", err)
	}

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal report: %v", err)
	}

	fmt.Println(string(reportJSON))
}
