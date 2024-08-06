package grpc

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/protobuf/proto"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
)

// PerformGRPCScan performs a gRPC scan against a target URL and returns the report.
func PerformGRPCScan(ctx context.Context, target string) (webscan.Report, error) {
	report := webscan.Report{Target: target, BaseEndpointUrl: target, AppType: webscan.ApiTypeGrpc}

	// Connect to the gRPC server
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock(), grpc.WithTimeout(60*time.Second))
	if err != nil {
		return report, fmt.Errorf("failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	// Create a new reflection client
	client := grpc_reflection_v1alpha.NewServerReflectionClient(conn)
	stream, err := client.ServerReflectionInfo(ctx)
	if err != nil {
		return report, fmt.Errorf("failed to create reflection client: %v", err)
	}

	// Request the list of services
	if err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{
			ListServices: "*",
		},
	}); err != nil {
		return report, fmt.Errorf("failed to request list of services: %v", err)
	}

	// Receive the list of services
	resp, err := stream.Recv()
	if err != nil {
		return report, fmt.Errorf("failed to receive list of services: %v", err)
	}

	services := resp.GetListServicesResponse().Service
	var rawDescriptors []*descriptorpb.FileDescriptorProto

	// Iterate over services to populate the report
	for _, service := range services {
		serviceName := service.Name

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

		fileDescriptorBytes := resp.GetFileDescriptorResponse().FileDescriptorProto
		for _, fdBytes := range fileDescriptorBytes {
			var fileDesc descriptorpb.FileDescriptorProto
			if err := proto.Unmarshal(fdBytes, &fileDesc); err != nil {
				return report, fmt.Errorf("failed to unmarshal file descriptor: %v", err)
			}
			rawDescriptors = append(rawDescriptors, &fileDesc)

			// Extract methods and their input types from the file descriptor
			for _, service := range fileDesc.Service {
				for _, method := range service.Method {
					queryParams := extractFields(&fileDesc, method.GetInputType())
					route := webscan.Route{
						Path:        fmt.Sprintf("/%s/%s", service.GetName(), method.GetName()),
						Method:      "POST",
						Auth:        nil,
						Queryparams: queryParams,
						Type:        webscan.ApiTypeGrpc,
						Description: method.GetName(),
					}
					report.Routes = append(report.Routes, &route)
				}
			}
		}
	}

	// Encode the raw descriptors in base64 and add to the report
	rawData, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: rawDescriptors})
	if err != nil {
		return report, fmt.Errorf("failed to marshal raw descriptors: %v", err)
	}
	report.Raw = base64.StdEncoding.EncodeToString(rawData)

	return report, nil
}

// extracts the fields of a given message type from the file descriptor.
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
