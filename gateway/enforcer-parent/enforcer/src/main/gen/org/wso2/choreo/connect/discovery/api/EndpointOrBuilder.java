// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wso2/discovery/api/Endpoint.proto

package org.wso2.choreo.connect.discovery.api;

public interface EndpointOrBuilder extends
    // @@protoc_insertion_point(interface_extends:wso2.discovery.api.Endpoint)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>string host = 1;</code>
   * @return The host.
   */
  java.lang.String getHost();
  /**
   * <code>string host = 1;</code>
   * @return The bytes for host.
   */
  com.google.protobuf.ByteString
      getHostBytes();

  /**
   * <code>string basepath = 2;</code>
   * @return The basepath.
   */
  java.lang.String getBasepath();
  /**
   * <code>string basepath = 2;</code>
   * @return The bytes for basepath.
   */
  com.google.protobuf.ByteString
      getBasepathBytes();

  /**
   * <code>string uRLType = 3;</code>
   * @return The uRLType.
   */
  java.lang.String getURLType();
  /**
   * <code>string uRLType = 3;</code>
   * @return The bytes for uRLType.
   */
  com.google.protobuf.ByteString
      getURLTypeBytes();

  /**
   * <code>uint32 port = 4;</code>
   * @return The port.
   */
  int getPort();
}
