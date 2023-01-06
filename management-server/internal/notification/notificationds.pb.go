//
//  Copyright (c) 2022, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.13.0
// source: wso2/discovery/service/apkmgt/notificationds.proto

package notification

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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

type NotificationResponse_StatusCode int32

const (
	// The response code is not known.
	NotificationResponse_UNKNOWN NotificationResponse_StatusCode = 0
	// The response code to notify that the number of requests are under limit.
	NotificationResponse_OK NotificationResponse_StatusCode = 1
	// The response code to notify that the number of requests are over limit.
	NotificationResponse_FAILED NotificationResponse_StatusCode = 2
)

// Enum value maps for NotificationResponse_StatusCode.
var (
	NotificationResponse_StatusCode_name = map[int32]string{
		0: "UNKNOWN",
		1: "OK",
		2: "FAILED",
	}
	NotificationResponse_StatusCode_value = map[string]int32{
		"UNKNOWN": 0,
		"OK":      1,
		"FAILED":  2,
	}
)

func (x NotificationResponse_StatusCode) Enum() *NotificationResponse_StatusCode {
	p := new(NotificationResponse_StatusCode)
	*p = x
	return p
}

func (x NotificationResponse_StatusCode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (NotificationResponse_StatusCode) Descriptor() protoreflect.EnumDescriptor {
	return file_wso2_discovery_service_apkmgt_notificationds_proto_enumTypes[0].Descriptor()
}

func (NotificationResponse_StatusCode) Type() protoreflect.EnumType {
	return &file_wso2_discovery_service_apkmgt_notificationds_proto_enumTypes[0]
}

func (x NotificationResponse_StatusCode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use NotificationResponse_StatusCode.Descriptor instead.
func (NotificationResponse_StatusCode) EnumDescriptor() ([]byte, []int) {
	return file_wso2_discovery_service_apkmgt_notificationds_proto_rawDescGZIP(), []int{2, 0}
}

type Application struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EventId       string `protobuf:"bytes,1,opt,name=eventId,proto3" json:"eventId,omitempty"`
	ApplicationId string `protobuf:"bytes,2,opt,name=applicationId,proto3" json:"applicationId,omitempty"`
	Uuid          string `protobuf:"bytes,3,opt,name=uuid,proto3" json:"uuid,omitempty"`
	TimeStamp     string `protobuf:"bytes,4,opt,name=timeStamp,proto3" json:"timeStamp,omitempty"`
	Organization  string `protobuf:"bytes,5,opt,name=organization,proto3" json:"organization,omitempty"`
}

func (x *Application) Reset() {
	*x = Application{}
	if protoimpl.UnsafeEnabled {
		mi := &file_wso2_discovery_service_apkmgt_notificationds_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Application) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Application) ProtoMessage() {}

func (x *Application) ProtoReflect() protoreflect.Message {
	mi := &file_wso2_discovery_service_apkmgt_notificationds_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Application.ProtoReflect.Descriptor instead.
func (*Application) Descriptor() ([]byte, []int) {
	return file_wso2_discovery_service_apkmgt_notificationds_proto_rawDescGZIP(), []int{0}
}

func (x *Application) GetEventId() string {
	if x != nil {
		return x.EventId
	}
	return ""
}

func (x *Application) GetApplicationId() string {
	if x != nil {
		return x.ApplicationId
	}
	return ""
}

func (x *Application) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *Application) GetTimeStamp() string {
	if x != nil {
		return x.TimeStamp
	}
	return ""
}

func (x *Application) GetOrganization() string {
	if x != nil {
		return x.Organization
	}
	return ""
}

type Subscription struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EventId       string `protobuf:"bytes,1,opt,name=eventId,proto3" json:"eventId,omitempty"`
	ApplicationId string `protobuf:"bytes,2,opt,name=applicationId,proto3" json:"applicationId,omitempty"`
	Uuid          string `protobuf:"bytes,3,opt,name=uuid,proto3" json:"uuid,omitempty"`
	TimeStamp     string `protobuf:"bytes,4,opt,name=timeStamp,proto3" json:"timeStamp,omitempty"`
	Organization  string `protobuf:"bytes,5,opt,name=organization,proto3" json:"organization,omitempty"`
}

func (x *Subscription) Reset() {
	*x = Subscription{}
	if protoimpl.UnsafeEnabled {
		mi := &file_wso2_discovery_service_apkmgt_notificationds_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Subscription) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Subscription) ProtoMessage() {}

func (x *Subscription) ProtoReflect() protoreflect.Message {
	mi := &file_wso2_discovery_service_apkmgt_notificationds_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Subscription.ProtoReflect.Descriptor instead.
func (*Subscription) Descriptor() ([]byte, []int) {
	return file_wso2_discovery_service_apkmgt_notificationds_proto_rawDescGZIP(), []int{1}
}

func (x *Subscription) GetEventId() string {
	if x != nil {
		return x.EventId
	}
	return ""
}

func (x *Subscription) GetApplicationId() string {
	if x != nil {
		return x.ApplicationId
	}
	return ""
}

func (x *Subscription) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *Subscription) GetTimeStamp() string {
	if x != nil {
		return x.TimeStamp
	}
	return ""
}

func (x *Subscription) GetOrganization() string {
	if x != nil {
		return x.Organization
	}
	return ""
}

type NotificationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code NotificationResponse_StatusCode `protobuf:"varint,1,opt,name=code,proto3,enum=discovery.service.apkmgt.NotificationResponse_StatusCode" json:"code,omitempty"`
}

func (x *NotificationResponse) Reset() {
	*x = NotificationResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_wso2_discovery_service_apkmgt_notificationds_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NotificationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NotificationResponse) ProtoMessage() {}

func (x *NotificationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_wso2_discovery_service_apkmgt_notificationds_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NotificationResponse.ProtoReflect.Descriptor instead.
func (*NotificationResponse) Descriptor() ([]byte, []int) {
	return file_wso2_discovery_service_apkmgt_notificationds_proto_rawDescGZIP(), []int{2}
}

func (x *NotificationResponse) GetCode() NotificationResponse_StatusCode {
	if x != nil {
		return x.Code
	}
	return NotificationResponse_UNKNOWN
}

var File_wso2_discovery_service_apkmgt_notificationds_proto protoreflect.FileDescriptor

var file_wso2_discovery_service_apkmgt_notificationds_proto_rawDesc = []byte{
	0x0a, 0x32, 0x77, 0x73, 0x6f, 0x32, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79,
	0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2f, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x2f,
	0x6e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x64, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x18, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x22, 0xa3,
	0x01, 0x0a, 0x0b, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x18,
	0x0a, 0x07, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x0d, 0x61, 0x70, 0x70, 0x6c,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0d, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x12,
	0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x75,
	0x69, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x53, 0x74, 0x61, 0x6d, 0x70, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x53, 0x74, 0x61, 0x6d, 0x70,
	0x12, 0x22, 0x0a, 0x0c, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x22, 0xa4, 0x01, 0x0a, 0x0c, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x49, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12,
	0x24, 0x0a, 0x0d, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x75, 0x69, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d,
	0x65, 0x53, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x74, 0x69,
	0x6d, 0x65, 0x53, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x22, 0x0a, 0x0c, 0x6f, 0x72, 0x67, 0x61, 0x6e,
	0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x6f,
	0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x94, 0x01, 0x0a, 0x14,
	0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4d, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x39, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x2e, 0x4e, 0x6f,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x43, 0x6f, 0x64, 0x65, 0x52, 0x04, 0x63,
	0x6f, 0x64, 0x65, 0x22, 0x2d, 0x0a, 0x0a, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x43, 0x6f, 0x64,
	0x65, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x06,
	0x0a, 0x02, 0x4f, 0x4b, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x46, 0x41, 0x49, 0x4c, 0x45, 0x44,
	0x10, 0x02, 0x32, 0xa3, 0x05, 0x0a, 0x13, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x6a, 0x0a, 0x11, 0x43, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x25, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x2e, 0x41, 0x70, 0x70, 0x6c, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x2e, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65,
	0x72, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b, 0x6d, 0x67,
	0x74, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x6a, 0x0a, 0x11, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x25, 0x2e, 0x64, 0x69,
	0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e,
	0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x2e, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x1a, 0x2e, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x2e, 0x4e, 0x6f,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x6a, 0x0a, 0x11, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x70, 0x70, 0x6c,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x25, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76,
	0x65, 0x72, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b, 0x6d,
	0x67, 0x74, 0x2e, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x2e,
	0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x6c,
	0x0a, 0x12, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x26, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x2e,
	0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x2e, 0x2e, 0x64,
	0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x2e, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x6c, 0x0a, 0x12,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x26, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x2e, 0x53, 0x75,
	0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x2e, 0x2e, 0x64, 0x69, 0x73,
	0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61,
	0x70, 0x6b, 0x6d, 0x67, 0x74, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x6c, 0x0a, 0x12, 0x44, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x26, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x2e, 0x53, 0x75, 0x62, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x2e, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f,
	0x76, 0x65, 0x72, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b,
	0x6d, 0x67, 0x74, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x82, 0x01, 0x0a, 0x30, 0x6f, 0x72, 0x67,
	0x2e, 0x77, 0x73, 0x6f, 0x32, 0x2e, 0x63, 0x68, 0x6f, 0x72, 0x65, 0x6f, 0x2e, 0x63, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x42, 0x13, 0x6e,
	0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x44, 0x73, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x50, 0x00, 0x5a, 0x34, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x77, 0x73, 0x6f, 0x32, 0x2f, 0x61, 0x70, 0x6b, 0x2f, 0x61, 0x64, 0x61, 0x70, 0x74, 0x65,
	0x72, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2f, 0x61, 0x70, 0x6b, 0x6d, 0x67, 0x74, 0x88, 0x01, 0x01, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_wso2_discovery_service_apkmgt_notificationds_proto_rawDescOnce sync.Once
	file_wso2_discovery_service_apkmgt_notificationds_proto_rawDescData = file_wso2_discovery_service_apkmgt_notificationds_proto_rawDesc
)

func file_wso2_discovery_service_apkmgt_notificationds_proto_rawDescGZIP() []byte {
	file_wso2_discovery_service_apkmgt_notificationds_proto_rawDescOnce.Do(func() {
		file_wso2_discovery_service_apkmgt_notificationds_proto_rawDescData = protoimpl.X.CompressGZIP(file_wso2_discovery_service_apkmgt_notificationds_proto_rawDescData)
	})
	return file_wso2_discovery_service_apkmgt_notificationds_proto_rawDescData
}

var file_wso2_discovery_service_apkmgt_notificationds_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_wso2_discovery_service_apkmgt_notificationds_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_wso2_discovery_service_apkmgt_notificationds_proto_goTypes = []interface{}{
	(NotificationResponse_StatusCode)(0), // 0: discovery.service.apkmgt.NotificationResponse.StatusCode
	(*Application)(nil),                  // 1: discovery.service.apkmgt.Application
	(*Subscription)(nil),                 // 2: discovery.service.apkmgt.Subscription
	(*NotificationResponse)(nil),         // 3: discovery.service.apkmgt.NotificationResponse
}
var file_wso2_discovery_service_apkmgt_notificationds_proto_depIdxs = []int32{
	0, // 0: discovery.service.apkmgt.NotificationResponse.code:type_name -> discovery.service.apkmgt.NotificationResponse.StatusCode
	1, // 1: discovery.service.apkmgt.NotificationService.CreateApplication:input_type -> discovery.service.apkmgt.Application
	1, // 2: discovery.service.apkmgt.NotificationService.UpdateApplication:input_type -> discovery.service.apkmgt.Application
	1, // 3: discovery.service.apkmgt.NotificationService.DeleteApplication:input_type -> discovery.service.apkmgt.Application
	2, // 4: discovery.service.apkmgt.NotificationService.CreateSubscription:input_type -> discovery.service.apkmgt.Subscription
	2, // 5: discovery.service.apkmgt.NotificationService.UpdateSubscription:input_type -> discovery.service.apkmgt.Subscription
	2, // 6: discovery.service.apkmgt.NotificationService.DeleteSubscription:input_type -> discovery.service.apkmgt.Subscription
	3, // 7: discovery.service.apkmgt.NotificationService.CreateApplication:output_type -> discovery.service.apkmgt.NotificationResponse
	3, // 8: discovery.service.apkmgt.NotificationService.UpdateApplication:output_type -> discovery.service.apkmgt.NotificationResponse
	3, // 9: discovery.service.apkmgt.NotificationService.DeleteApplication:output_type -> discovery.service.apkmgt.NotificationResponse
	3, // 10: discovery.service.apkmgt.NotificationService.CreateSubscription:output_type -> discovery.service.apkmgt.NotificationResponse
	3, // 11: discovery.service.apkmgt.NotificationService.UpdateSubscription:output_type -> discovery.service.apkmgt.NotificationResponse
	3, // 12: discovery.service.apkmgt.NotificationService.DeleteSubscription:output_type -> discovery.service.apkmgt.NotificationResponse
	7, // [7:13] is the sub-list for method output_type
	1, // [1:7] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_wso2_discovery_service_apkmgt_notificationds_proto_init() }
func file_wso2_discovery_service_apkmgt_notificationds_proto_init() {
	if File_wso2_discovery_service_apkmgt_notificationds_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_wso2_discovery_service_apkmgt_notificationds_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Application); i {
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
		file_wso2_discovery_service_apkmgt_notificationds_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Subscription); i {
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
		file_wso2_discovery_service_apkmgt_notificationds_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NotificationResponse); i {
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
			RawDescriptor: file_wso2_discovery_service_apkmgt_notificationds_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_wso2_discovery_service_apkmgt_notificationds_proto_goTypes,
		DependencyIndexes: file_wso2_discovery_service_apkmgt_notificationds_proto_depIdxs,
		EnumInfos:         file_wso2_discovery_service_apkmgt_notificationds_proto_enumTypes,
		MessageInfos:      file_wso2_discovery_service_apkmgt_notificationds_proto_msgTypes,
	}.Build()
	File_wso2_discovery_service_apkmgt_notificationds_proto = out.File
	file_wso2_discovery_service_apkmgt_notificationds_proto_rawDesc = nil
	file_wso2_discovery_service_apkmgt_notificationds_proto_goTypes = nil
	file_wso2_discovery_service_apkmgt_notificationds_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// NotificationServiceClient is the client API for NotificationService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type NotificationServiceClient interface {
	CreateApplication(ctx context.Context, in *Application, opts ...grpc.CallOption) (*NotificationResponse, error)
	UpdateApplication(ctx context.Context, in *Application, opts ...grpc.CallOption) (*NotificationResponse, error)
	DeleteApplication(ctx context.Context, in *Application, opts ...grpc.CallOption) (*NotificationResponse, error)
	CreateSubscription(ctx context.Context, in *Subscription, opts ...grpc.CallOption) (*NotificationResponse, error)
	UpdateSubscription(ctx context.Context, in *Subscription, opts ...grpc.CallOption) (*NotificationResponse, error)
	DeleteSubscription(ctx context.Context, in *Subscription, opts ...grpc.CallOption) (*NotificationResponse, error)
}

type notificationServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewNotificationServiceClient(cc grpc.ClientConnInterface) NotificationServiceClient {
	return &notificationServiceClient{cc}
}

func (c *notificationServiceClient) CreateApplication(ctx context.Context, in *Application, opts ...grpc.CallOption) (*NotificationResponse, error) {
	out := new(NotificationResponse)
	err := c.cc.Invoke(ctx, "/discovery.service.apkmgt.NotificationService/CreateApplication", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *notificationServiceClient) UpdateApplication(ctx context.Context, in *Application, opts ...grpc.CallOption) (*NotificationResponse, error) {
	out := new(NotificationResponse)
	err := c.cc.Invoke(ctx, "/discovery.service.apkmgt.NotificationService/UpdateApplication", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *notificationServiceClient) DeleteApplication(ctx context.Context, in *Application, opts ...grpc.CallOption) (*NotificationResponse, error) {
	out := new(NotificationResponse)
	err := c.cc.Invoke(ctx, "/discovery.service.apkmgt.NotificationService/DeleteApplication", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *notificationServiceClient) CreateSubscription(ctx context.Context, in *Subscription, opts ...grpc.CallOption) (*NotificationResponse, error) {
	out := new(NotificationResponse)
	err := c.cc.Invoke(ctx, "/discovery.service.apkmgt.NotificationService/CreateSubscription", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *notificationServiceClient) UpdateSubscription(ctx context.Context, in *Subscription, opts ...grpc.CallOption) (*NotificationResponse, error) {
	out := new(NotificationResponse)
	err := c.cc.Invoke(ctx, "/discovery.service.apkmgt.NotificationService/UpdateSubscription", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *notificationServiceClient) DeleteSubscription(ctx context.Context, in *Subscription, opts ...grpc.CallOption) (*NotificationResponse, error) {
	out := new(NotificationResponse)
	err := c.cc.Invoke(ctx, "/discovery.service.apkmgt.NotificationService/DeleteSubscription", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NotificationServiceServer is the server API for NotificationService service.
type NotificationServiceServer interface {
	CreateApplication(context.Context, *Application) (*NotificationResponse, error)
	UpdateApplication(context.Context, *Application) (*NotificationResponse, error)
	DeleteApplication(context.Context, *Application) (*NotificationResponse, error)
	CreateSubscription(context.Context, *Subscription) (*NotificationResponse, error)
	UpdateSubscription(context.Context, *Subscription) (*NotificationResponse, error)
	DeleteSubscription(context.Context, *Subscription) (*NotificationResponse, error)
}

// UnimplementedNotificationServiceServer can be embedded to have forward compatible implementations.
type UnimplementedNotificationServiceServer struct {
}

func (*UnimplementedNotificationServiceServer) CreateApplication(context.Context, *Application) (*NotificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateApplication not implemented")
}
func (*UnimplementedNotificationServiceServer) UpdateApplication(context.Context, *Application) (*NotificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateApplication not implemented")
}
func (*UnimplementedNotificationServiceServer) DeleteApplication(context.Context, *Application) (*NotificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteApplication not implemented")
}
func (*UnimplementedNotificationServiceServer) CreateSubscription(context.Context, *Subscription) (*NotificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateSubscription not implemented")
}
func (*UnimplementedNotificationServiceServer) UpdateSubscription(context.Context, *Subscription) (*NotificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateSubscription not implemented")
}
func (*UnimplementedNotificationServiceServer) DeleteSubscription(context.Context, *Subscription) (*NotificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteSubscription not implemented")
}

func RegisterNotificationServiceServer(s *grpc.Server, srv NotificationServiceServer) {
	s.RegisterService(&_NotificationService_serviceDesc, srv)
}

func _NotificationService_CreateApplication_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Application)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NotificationServiceServer).CreateApplication(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/discovery.service.apkmgt.NotificationService/CreateApplication",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NotificationServiceServer).CreateApplication(ctx, req.(*Application))
	}
	return interceptor(ctx, in, info, handler)
}

func _NotificationService_UpdateApplication_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Application)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NotificationServiceServer).UpdateApplication(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/discovery.service.apkmgt.NotificationService/UpdateApplication",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NotificationServiceServer).UpdateApplication(ctx, req.(*Application))
	}
	return interceptor(ctx, in, info, handler)
}

func _NotificationService_DeleteApplication_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Application)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NotificationServiceServer).DeleteApplication(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/discovery.service.apkmgt.NotificationService/DeleteApplication",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NotificationServiceServer).DeleteApplication(ctx, req.(*Application))
	}
	return interceptor(ctx, in, info, handler)
}

func _NotificationService_CreateSubscription_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Subscription)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NotificationServiceServer).CreateSubscription(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/discovery.service.apkmgt.NotificationService/CreateSubscription",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NotificationServiceServer).CreateSubscription(ctx, req.(*Subscription))
	}
	return interceptor(ctx, in, info, handler)
}

func _NotificationService_UpdateSubscription_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Subscription)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NotificationServiceServer).UpdateSubscription(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/discovery.service.apkmgt.NotificationService/UpdateSubscription",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NotificationServiceServer).UpdateSubscription(ctx, req.(*Subscription))
	}
	return interceptor(ctx, in, info, handler)
}

func _NotificationService_DeleteSubscription_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Subscription)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NotificationServiceServer).DeleteSubscription(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/discovery.service.apkmgt.NotificationService/DeleteSubscription",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NotificationServiceServer).DeleteSubscription(ctx, req.(*Subscription))
	}
	return interceptor(ctx, in, info, handler)
}

var _NotificationService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "discovery.service.apkmgt.NotificationService",
	HandlerType: (*NotificationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateApplication",
			Handler:    _NotificationService_CreateApplication_Handler,
		},
		{
			MethodName: "UpdateApplication",
			Handler:    _NotificationService_UpdateApplication_Handler,
		},
		{
			MethodName: "DeleteApplication",
			Handler:    _NotificationService_DeleteApplication_Handler,
		},
		{
			MethodName: "CreateSubscription",
			Handler:    _NotificationService_CreateSubscription_Handler,
		},
		{
			MethodName: "UpdateSubscription",
			Handler:    _NotificationService_UpdateSubscription_Handler,
		},
		{
			MethodName: "DeleteSubscription",
			Handler:    _NotificationService_DeleteSubscription_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "wso2/discovery/service/apkmgt/notificationds.proto",
}
