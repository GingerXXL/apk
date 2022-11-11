// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wso2/discovery/config/enforcer/tm_url_group.proto

package org.wso2.choreo.connect.discovery.config.enforcer;

public interface TMURLGroupOrBuilder extends
    // @@protoc_insertion_point(interface_extends:wso2.discovery.config.enforcer.TMURLGroup)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>repeated string receiverURLs = 1;</code>
   * @return A list containing the receiverURLs.
   */
  java.util.List<java.lang.String>
      getReceiverURLsList();
  /**
   * <code>repeated string receiverURLs = 1;</code>
   * @return The count of receiverURLs.
   */
  int getReceiverURLsCount();
  /**
   * <code>repeated string receiverURLs = 1;</code>
   * @param index The index of the element to return.
   * @return The receiverURLs at the given index.
   */
  java.lang.String getReceiverURLs(int index);
  /**
   * <code>repeated string receiverURLs = 1;</code>
   * @param index The index of the value to return.
   * @return The bytes of the receiverURLs at the given index.
   */
  com.google.protobuf.ByteString
      getReceiverURLsBytes(int index);

  /**
   * <code>repeated string authURLs = 2;</code>
   * @return A list containing the authURLs.
   */
  java.util.List<java.lang.String>
      getAuthURLsList();
  /**
   * <code>repeated string authURLs = 2;</code>
   * @return The count of authURLs.
   */
  int getAuthURLsCount();
  /**
   * <code>repeated string authURLs = 2;</code>
   * @param index The index of the element to return.
   * @return The authURLs at the given index.
   */
  java.lang.String getAuthURLs(int index);
  /**
   * <code>repeated string authURLs = 2;</code>
   * @param index The index of the value to return.
   * @return The bytes of the authURLs at the given index.
   */
  com.google.protobuf.ByteString
      getAuthURLsBytes(int index);

  /**
   * <code>string type = 3;</code>
   * @return The type.
   */
  java.lang.String getType();
  /**
   * <code>string type = 3;</code>
   * @return The bytes for type.
   */
  com.google.protobuf.ByteString
      getTypeBytes();
}
