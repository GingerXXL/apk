// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.13.0
// source: wso2/discovery/service/config/cds.proto

package config

import (
	context "context"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_wso2_discovery_service_config_cds_proto protoreflect.FileDescriptor

var file_wso2_discovery_service_config_cds_proto_rawDesc = []byte{
	0x0a, 0x27, 0x77, 0x73, 0x6f, 0x32, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79,
	0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f,
	0x63, 0x64, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x18, 0x64, 0x69, 0x73, 0x63, 0x6f,
	0x76, 0x65, 0x72, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x1a, 0x2a, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x76, 0x33, 0x2f,
	0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x32,
	0xfb, 0x01, 0x0a, 0x16, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76,
	0x65, 0x72, 0x79, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x72, 0x0a, 0x0d, 0x53, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x12, 0x2c, 0x2e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x64, 0x69, 0x73, 0x63,
	0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x76, 0x33, 0x2e, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65,
	0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2d, 0x2e, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76,
	0x65, 0x72, 0x79, 0x2e, 0x76, 0x33, 0x2e, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x28, 0x01, 0x30, 0x01, 0x12, 0x6d,
	0x0a, 0x0c, 0x46, 0x65, 0x74, 0x63, 0x68, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x12, 0x2c,
	0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x64,
	0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x76, 0x33, 0x2e, 0x44, 0x69, 0x73, 0x63,
	0x6f, 0x76, 0x65, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2d, 0x2e, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x64, 0x69, 0x73,
	0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x76, 0x33, 0x2e, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76,
	0x65, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x7c, 0x0a,
	0x25, 0x6f, 0x72, 0x67, 0x2e, 0x77, 0x73, 0x6f, 0x32, 0x2e, 0x61, 0x70, 0x6b, 0x2e, 0x64, 0x69,
	0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x42, 0x08, 0x43, 0x64, 0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x50, 0x01, 0x5a, 0x44, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x77, 0x73, 0x6f, 0x32, 0x2f,
	0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x88, 0x01, 0x01, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var file_wso2_discovery_service_config_cds_proto_goTypes = []interface{}{
	(*v3.DiscoveryRequest)(nil),  // 0: envoy.service.discovery.v3.DiscoveryRequest
	(*v3.DiscoveryResponse)(nil), // 1: envoy.service.discovery.v3.DiscoveryResponse
}
var file_wso2_discovery_service_config_cds_proto_depIdxs = []int32{
	0, // 0: discovery.service.config.ConfigDiscoveryService.StreamConfigs:input_type -> envoy.service.discovery.v3.DiscoveryRequest
	0, // 1: discovery.service.config.ConfigDiscoveryService.FetchConfigs:input_type -> envoy.service.discovery.v3.DiscoveryRequest
	1, // 2: discovery.service.config.ConfigDiscoveryService.StreamConfigs:output_type -> envoy.service.discovery.v3.DiscoveryResponse
	1, // 3: discovery.service.config.ConfigDiscoveryService.FetchConfigs:output_type -> envoy.service.discovery.v3.DiscoveryResponse
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_wso2_discovery_service_config_cds_proto_init() }
func file_wso2_discovery_service_config_cds_proto_init() {
	if File_wso2_discovery_service_config_cds_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_wso2_discovery_service_config_cds_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_wso2_discovery_service_config_cds_proto_goTypes,
		DependencyIndexes: file_wso2_discovery_service_config_cds_proto_depIdxs,
	}.Build()
	File_wso2_discovery_service_config_cds_proto = out.File
	file_wso2_discovery_service_config_cds_proto_rawDesc = nil
	file_wso2_discovery_service_config_cds_proto_goTypes = nil
	file_wso2_discovery_service_config_cds_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// ConfigDiscoveryServiceClient is the client API for ConfigDiscoveryService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ConfigDiscoveryServiceClient interface {
	StreamConfigs(ctx context.Context, opts ...grpc.CallOption) (ConfigDiscoveryService_StreamConfigsClient, error)
	FetchConfigs(ctx context.Context, in *v3.DiscoveryRequest, opts ...grpc.CallOption) (*v3.DiscoveryResponse, error)
}

type configDiscoveryServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewConfigDiscoveryServiceClient(cc grpc.ClientConnInterface) ConfigDiscoveryServiceClient {
	return &configDiscoveryServiceClient{cc}
}

func (c *configDiscoveryServiceClient) StreamConfigs(ctx context.Context, opts ...grpc.CallOption) (ConfigDiscoveryService_StreamConfigsClient, error) {
	stream, err := c.cc.NewStream(ctx, &_ConfigDiscoveryService_serviceDesc.Streams[0], "/discovery.service.config.ConfigDiscoveryService/StreamConfigs", opts...)
	if err != nil {
		return nil, err
	}
	x := &configDiscoveryServiceStreamConfigsClient{stream}
	return x, nil
}

type ConfigDiscoveryService_StreamConfigsClient interface {
	Send(*v3.DiscoveryRequest) error
	Recv() (*v3.DiscoveryResponse, error)
	grpc.ClientStream
}

type configDiscoveryServiceStreamConfigsClient struct {
	grpc.ClientStream
}

func (x *configDiscoveryServiceStreamConfigsClient) Send(m *v3.DiscoveryRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *configDiscoveryServiceStreamConfigsClient) Recv() (*v3.DiscoveryResponse, error) {
	m := new(v3.DiscoveryResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *configDiscoveryServiceClient) FetchConfigs(ctx context.Context, in *v3.DiscoveryRequest, opts ...grpc.CallOption) (*v3.DiscoveryResponse, error) {
	out := new(v3.DiscoveryResponse)
	err := c.cc.Invoke(ctx, "/discovery.service.config.ConfigDiscoveryService/FetchConfigs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConfigDiscoveryServiceServer is the server API for ConfigDiscoveryService service.
type ConfigDiscoveryServiceServer interface {
	StreamConfigs(ConfigDiscoveryService_StreamConfigsServer) error
	FetchConfigs(context.Context, *v3.DiscoveryRequest) (*v3.DiscoveryResponse, error)
}

// UnimplementedConfigDiscoveryServiceServer can be embedded to have forward compatible implementations.
type UnimplementedConfigDiscoveryServiceServer struct {
}

func (*UnimplementedConfigDiscoveryServiceServer) StreamConfigs(ConfigDiscoveryService_StreamConfigsServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamConfigs not implemented")
}
func (*UnimplementedConfigDiscoveryServiceServer) FetchConfigs(context.Context, *v3.DiscoveryRequest) (*v3.DiscoveryResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FetchConfigs not implemented")
}

func RegisterConfigDiscoveryServiceServer(s *grpc.Server, srv ConfigDiscoveryServiceServer) {
	s.RegisterService(&_ConfigDiscoveryService_serviceDesc, srv)
}

func _ConfigDiscoveryService_StreamConfigs_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ConfigDiscoveryServiceServer).StreamConfigs(&configDiscoveryServiceStreamConfigsServer{stream})
}

type ConfigDiscoveryService_StreamConfigsServer interface {
	Send(*v3.DiscoveryResponse) error
	Recv() (*v3.DiscoveryRequest, error)
	grpc.ServerStream
}

type configDiscoveryServiceStreamConfigsServer struct {
	grpc.ServerStream
}

func (x *configDiscoveryServiceStreamConfigsServer) Send(m *v3.DiscoveryResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *configDiscoveryServiceStreamConfigsServer) Recv() (*v3.DiscoveryRequest, error) {
	m := new(v3.DiscoveryRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _ConfigDiscoveryService_FetchConfigs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(v3.DiscoveryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConfigDiscoveryServiceServer).FetchConfigs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/discovery.service.config.ConfigDiscoveryService/FetchConfigs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConfigDiscoveryServiceServer).FetchConfigs(ctx, req.(*v3.DiscoveryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _ConfigDiscoveryService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "discovery.service.config.ConfigDiscoveryService",
	HandlerType: (*ConfigDiscoveryServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "FetchConfigs",
			Handler:    _ConfigDiscoveryService_FetchConfigs_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamConfigs",
			Handler:       _ConfigDiscoveryService_StreamConfigs_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "wso2/discovery/service/config/cds.proto",
}
