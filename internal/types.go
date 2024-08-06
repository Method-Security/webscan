package types

type APIType string

const (
	GRPC      APIType = "grpc"
	GraphQL   APIType = "graphql"
	SwaggerV2 APIType = "swaggerv2"
	SwaggerV3 APIType = "swaggerv3"
)
