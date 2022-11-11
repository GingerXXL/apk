// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wso2/discovery/api/endpoint_cluster.proto

package org.wso2.choreo.connect.discovery.api;

public interface RetryConfigOrBuilder extends
    // @@protoc_insertion_point(interface_extends:wso2.discovery.api.RetryConfig)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>uint32 count = 1;</code>
   * @return The count.
   */
  int getCount();

  /**
   * <code>repeated uint32 statusCodes = 2;</code>
   * @return A list containing the statusCodes.
   */
  java.util.List<java.lang.Integer> getStatusCodesList();
  /**
   * <code>repeated uint32 statusCodes = 2;</code>
   * @return The count of statusCodes.
   */
  int getStatusCodesCount();
  /**
   * <code>repeated uint32 statusCodes = 2;</code>
   * @param index The index of the element to return.
   * @return The statusCodes at the given index.
   */
  int getStatusCodes(int index);
}
