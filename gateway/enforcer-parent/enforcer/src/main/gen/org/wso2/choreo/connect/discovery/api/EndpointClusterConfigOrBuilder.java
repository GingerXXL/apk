// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wso2/discovery/api/endpoint_cluster.proto

package org.wso2.choreo.connect.discovery.api;

public interface EndpointClusterConfigOrBuilder extends
    // @@protoc_insertion_point(interface_extends:wso2.discovery.api.EndpointClusterConfig)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.wso2.discovery.api.RetryConfig retryConfig = 1;</code>
   * @return Whether the retryConfig field is set.
   */
  boolean hasRetryConfig();
  /**
   * <code>.wso2.discovery.api.RetryConfig retryConfig = 1;</code>
   * @return The retryConfig.
   */
  org.wso2.choreo.connect.discovery.api.RetryConfig getRetryConfig();
  /**
   * <code>.wso2.discovery.api.RetryConfig retryConfig = 1;</code>
   */
  org.wso2.choreo.connect.discovery.api.RetryConfigOrBuilder getRetryConfigOrBuilder();

  /**
   * <code>.wso2.discovery.api.TimeoutConfig timeoutConfig = 2;</code>
   * @return Whether the timeoutConfig field is set.
   */
  boolean hasTimeoutConfig();
  /**
   * <code>.wso2.discovery.api.TimeoutConfig timeoutConfig = 2;</code>
   * @return The timeoutConfig.
   */
  org.wso2.choreo.connect.discovery.api.TimeoutConfig getTimeoutConfig();
  /**
   * <code>.wso2.discovery.api.TimeoutConfig timeoutConfig = 2;</code>
   */
  org.wso2.choreo.connect.discovery.api.TimeoutConfigOrBuilder getTimeoutConfigOrBuilder();
}
