// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wso2/discovery/service/api/apids.proto

package org.wso2.choreo.connect.discovery.service.api;

public final class APIDsProto {
  private APIDsProto() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n&wso2/discovery/service/api/apids.proto" +
      "\022\025discovery.service.api\032*envoy/service/d" +
      "iscovery/v3/discovery.proto2\362\001\n\023ApiDisco" +
      "veryService\022o\n\nStreamApis\022,.envoy.servic" +
      "e.discovery.v3.DiscoveryRequest\032-.envoy." +
      "service.discovery.v3.DiscoveryResponse\"\000" +
      "(\0010\001\022j\n\tFetchApis\022,.envoy.service.discov" +
      "ery.v3.DiscoveryRequest\032-.envoy.service." +
      "discovery.v3.DiscoveryResponse\"\000B\203\001\n-org" +
      ".wso2.choreo.connect.discovery.service.a" +
      "piB\nAPIDsProtoP\001ZAgithub.com/envoyproxy/" +
      "go-control-plane/wso2/discovery/service/" +
      "api\210\001\001b\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          io.envoyproxy.envoy.service.discovery.v3.DiscoveryProto.getDescriptor(),
        });
    io.envoyproxy.envoy.service.discovery.v3.DiscoveryProto.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
