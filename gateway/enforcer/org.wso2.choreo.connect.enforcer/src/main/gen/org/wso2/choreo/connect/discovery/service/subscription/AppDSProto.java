// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wso2/discovery/service/subscription/appds.proto

package org.wso2.choreo.connect.discovery.service.subscription;

public final class AppDSProto {
  private AppDSProto() {}
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
      "\n/wso2/discovery/service/subscription/ap" +
      "pds.proto\022\036discovery.service.subscriptio" +
      "n\032*envoy/service/discovery/v3/discovery." +
      "proto2\226\001\n\033ApplicationDiscoveryService\022w\n" +
      "\022StreamApplications\022,.envoy.service.disc" +
      "overy.v3.DiscoveryRequest\032-.envoy.servic" +
      "e.discovery.v3.DiscoveryResponse\"\000(\0010\001B\225" +
      "\001\n6org.wso2.choreo.connect.discovery.ser" +
      "vice.subscriptionB\nAppDSProtoP\001ZJgithub." +
      "com/envoyproxy/go-control-plane/wso2/dis" +
      "covery/service/subscription\210\001\001b\006proto3"
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
