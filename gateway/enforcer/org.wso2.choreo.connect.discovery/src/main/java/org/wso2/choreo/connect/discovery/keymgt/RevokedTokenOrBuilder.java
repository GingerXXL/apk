// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wso2/discovery/keymgt/revoked_tokens.proto

package org.wso2.choreo.connect.discovery.keymgt;

public interface RevokedTokenOrBuilder extends
    // @@protoc_insertion_point(interface_extends:wso2.discovery.keymgt.RevokedToken)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>string jti = 1;</code>
   * @return The jti.
   */
  java.lang.String getJti();
  /**
   * <code>string jti = 1;</code>
   * @return The bytes for jti.
   */
  com.google.protobuf.ByteString
      getJtiBytes();

  /**
   * <code>int64 expirytime = 2;</code>
   * @return The expirytime.
   */
  long getExpirytime();
}
