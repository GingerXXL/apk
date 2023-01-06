// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.13.0
// source: wso2/discovery/config/enforcer/binary_publisher.proto

package enforcer

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type BinaryPublisher struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Username string         `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	Password string         `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
	UrlGroup []*TMURLGroup  `protobuf:"bytes,3,rep,name=urlGroup,proto3" json:"urlGroup,omitempty"`
	Pool     *PublisherPool `protobuf:"bytes,4,opt,name=pool,proto3" json:"pool,omitempty"`
	Agent    *ThrottleAgent `protobuf:"bytes,5,opt,name=agent,proto3" json:"agent,omitempty"`
}

func (x *BinaryPublisher) Reset() {
	*x = BinaryPublisher{}
	if protoimpl.UnsafeEnabled {
		mi := &file_wso2_discovery_config_enforcer_binary_publisher_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BinaryPublisher) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BinaryPublisher) ProtoMessage() {}

func (x *BinaryPublisher) ProtoReflect() protoreflect.Message {
	mi := &file_wso2_discovery_config_enforcer_binary_publisher_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BinaryPublisher.ProtoReflect.Descriptor instead.
func (*BinaryPublisher) Descriptor() ([]byte, []int) {
	return file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDescGZIP(), []int{0}
}

func (x *BinaryPublisher) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *BinaryPublisher) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

func (x *BinaryPublisher) GetUrlGroup() []*TMURLGroup {
	if x != nil {
		return x.UrlGroup
	}
	return nil
}

func (x *BinaryPublisher) GetPool() *PublisherPool {
	if x != nil {
		return x.Pool
	}
	return nil
}

func (x *BinaryPublisher) GetAgent() *ThrottleAgent {
	if x != nil {
		return x.Agent
	}
	return nil
}

var File_wso2_discovery_config_enforcer_binary_publisher_proto protoreflect.FileDescriptor

var file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDesc = []byte{
	0x0a, 0x35, 0x77, 0x73, 0x6f, 0x32, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79,
	0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x65, 0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x72,
	0x2f, 0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65,
	0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1e, 0x77, 0x73, 0x6f, 0x32, 0x2e, 0x64, 0x69,
	0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x65,
	0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x72, 0x1a, 0x31, 0x77, 0x73, 0x6f, 0x32, 0x2f, 0x64, 0x69,
	0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x65,
	0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x72, 0x2f, 0x74, 0x6d, 0x5f, 0x75, 0x72, 0x6c, 0x5f, 0x67,
	0x72, 0x6f, 0x75, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x3c, 0x77, 0x73, 0x6f, 0x32,
	0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2f, 0x65, 0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x72, 0x2f, 0x74, 0x68, 0x72, 0x6f, 0x74,
	0x74, 0x6c, 0x65, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65, 0x72, 0x5f, 0x70, 0x6f,
	0x6f, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x33, 0x77, 0x73, 0x6f, 0x32, 0x2f, 0x64,
	0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f,
	0x65, 0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x72, 0x2f, 0x74, 0x68, 0x72, 0x6f, 0x74, 0x74, 0x6c,
	0x65, 0x5f, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x99, 0x02,
	0x0a, 0x0f, 0x42, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65,
	0x72, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a,
	0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x46, 0x0a, 0x08, 0x75, 0x72, 0x6c,
	0x47, 0x72, 0x6f, 0x75, 0x70, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x77, 0x73,
	0x6f, 0x32, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x65, 0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x72, 0x2e, 0x54, 0x4d, 0x55,
	0x52, 0x4c, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x52, 0x08, 0x75, 0x72, 0x6c, 0x47, 0x72, 0x6f, 0x75,
	0x70, 0x12, 0x41, 0x0a, 0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x2d, 0x2e, 0x77, 0x73, 0x6f, 0x32, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x65, 0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x72,
	0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65, 0x72, 0x50, 0x6f, 0x6f, 0x6c, 0x52, 0x04,
	0x70, 0x6f, 0x6f, 0x6c, 0x12, 0x43, 0x0a, 0x05, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x77, 0x73, 0x6f, 0x32, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f,
	0x76, 0x65, 0x72, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x65, 0x6e, 0x66, 0x6f,
	0x72, 0x63, 0x65, 0x72, 0x2e, 0x54, 0x68, 0x72, 0x6f, 0x74, 0x74, 0x6c, 0x65, 0x41, 0x67, 0x65,
	0x6e, 0x74, 0x52, 0x05, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x42, 0x9b, 0x01, 0x0a, 0x31, 0x6f, 0x72,
	0x67, 0x2e, 0x77, 0x73, 0x6f, 0x32, 0x2e, 0x63, 0x68, 0x6f, 0x72, 0x65, 0x6f, 0x2e, 0x63, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x65, 0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x72, 0x42,
	0x14, 0x42, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65, 0x72,
	0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x4e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67,
	0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f,
	0x77, 0x73, 0x6f, 0x32, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x65, 0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x72, 0x3b, 0x65,
	0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDescOnce sync.Once
	file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDescData = file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDesc
)

func file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDescGZIP() []byte {
	file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDescOnce.Do(func() {
		file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDescData = protoimpl.X.CompressGZIP(file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDescData)
	})
	return file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDescData
}

var file_wso2_discovery_config_enforcer_binary_publisher_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_wso2_discovery_config_enforcer_binary_publisher_proto_goTypes = []interface{}{
	(*BinaryPublisher)(nil), // 0: wso2.discovery.config.enforcer.BinaryPublisher
	(*TMURLGroup)(nil),      // 1: wso2.discovery.config.enforcer.TMURLGroup
	(*PublisherPool)(nil),   // 2: wso2.discovery.config.enforcer.PublisherPool
	(*ThrottleAgent)(nil),   // 3: wso2.discovery.config.enforcer.ThrottleAgent
}
var file_wso2_discovery_config_enforcer_binary_publisher_proto_depIdxs = []int32{
	1, // 0: wso2.discovery.config.enforcer.BinaryPublisher.urlGroup:type_name -> wso2.discovery.config.enforcer.TMURLGroup
	2, // 1: wso2.discovery.config.enforcer.BinaryPublisher.pool:type_name -> wso2.discovery.config.enforcer.PublisherPool
	3, // 2: wso2.discovery.config.enforcer.BinaryPublisher.agent:type_name -> wso2.discovery.config.enforcer.ThrottleAgent
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_wso2_discovery_config_enforcer_binary_publisher_proto_init() }
func file_wso2_discovery_config_enforcer_binary_publisher_proto_init() {
	if File_wso2_discovery_config_enforcer_binary_publisher_proto != nil {
		return
	}
	file_wso2_discovery_config_enforcer_tm_url_group_proto_init()
	file_wso2_discovery_config_enforcer_throttle_publisher_pool_proto_init()
	file_wso2_discovery_config_enforcer_throttle_agent_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_wso2_discovery_config_enforcer_binary_publisher_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BinaryPublisher); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_wso2_discovery_config_enforcer_binary_publisher_proto_goTypes,
		DependencyIndexes: file_wso2_discovery_config_enforcer_binary_publisher_proto_depIdxs,
		MessageInfos:      file_wso2_discovery_config_enforcer_binary_publisher_proto_msgTypes,
	}.Build()
	File_wso2_discovery_config_enforcer_binary_publisher_proto = out.File
	file_wso2_discovery_config_enforcer_binary_publisher_proto_rawDesc = nil
	file_wso2_discovery_config_enforcer_binary_publisher_proto_goTypes = nil
	file_wso2_discovery_config_enforcer_binary_publisher_proto_depIdxs = nil
}
