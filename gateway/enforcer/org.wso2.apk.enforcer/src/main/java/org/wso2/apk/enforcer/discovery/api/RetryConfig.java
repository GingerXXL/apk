// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wso2/discovery/api/endpoint_cluster.proto

package org.wso2.apk.enforcer.discovery.api;

/**
 * Protobuf type {@code wso2.discovery.api.RetryConfig}
 */
public final class RetryConfig extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:wso2.discovery.api.RetryConfig)
    RetryConfigOrBuilder {
private static final long serialVersionUID = 0L;
  // Use RetryConfig.newBuilder() to construct.
  private RetryConfig(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private RetryConfig() {
    statusCodes_ = com.google.protobuf.LazyStringArrayList.EMPTY;
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new RetryConfig();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private RetryConfig(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    this();
    if (extensionRegistry == null) {
      throw new java.lang.NullPointerException();
    }
    int mutable_bitField0_ = 0;
    com.google.protobuf.UnknownFieldSet.Builder unknownFields =
        com.google.protobuf.UnknownFieldSet.newBuilder();
    try {
      boolean done = false;
      while (!done) {
        int tag = input.readTag();
        switch (tag) {
          case 0:
            done = true;
            break;
          case 8: {

            count_ = input.readUInt32();
            break;
          }
          case 18: {
            java.lang.String s = input.readStringRequireUtf8();
            if (!((mutable_bitField0_ & 0x00000001) != 0)) {
              statusCodes_ = new com.google.protobuf.LazyStringArrayList();
              mutable_bitField0_ |= 0x00000001;
            }
            statusCodes_.add(s);
            break;
          }
          default: {
            if (!parseUnknownField(
                input, unknownFields, extensionRegistry, tag)) {
              done = true;
            }
            break;
          }
        }
      }
    } catch (com.google.protobuf.InvalidProtocolBufferException e) {
      throw e.setUnfinishedMessage(this);
    } catch (java.io.IOException e) {
      throw new com.google.protobuf.InvalidProtocolBufferException(
          e).setUnfinishedMessage(this);
    } finally {
      if (((mutable_bitField0_ & 0x00000001) != 0)) {
        statusCodes_ = statusCodes_.getUnmodifiableView();
      }
      this.unknownFields = unknownFields.build();
      makeExtensionsImmutable();
    }
  }
  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return org.wso2.apk.enforcer.discovery.api.EndpointClusterProto.internal_static_wso2_discovery_api_RetryConfig_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return org.wso2.apk.enforcer.discovery.api.EndpointClusterProto.internal_static_wso2_discovery_api_RetryConfig_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            org.wso2.apk.enforcer.discovery.api.RetryConfig.class, org.wso2.apk.enforcer.discovery.api.RetryConfig.Builder.class);
  }

  public static final int COUNT_FIELD_NUMBER = 1;
  private int count_;
  /**
   * <code>uint32 count = 1;</code>
   * @return The count.
   */
  @java.lang.Override
  public int getCount() {
    return count_;
  }

  public static final int STATUSCODES_FIELD_NUMBER = 2;
  private com.google.protobuf.LazyStringList statusCodes_;
  /**
   * <code>repeated string statusCodes = 2;</code>
   * @return A list containing the statusCodes.
   */
  public com.google.protobuf.ProtocolStringList
      getStatusCodesList() {
    return statusCodes_;
  }
  /**
   * <code>repeated string statusCodes = 2;</code>
   * @return The count of statusCodes.
   */
  public int getStatusCodesCount() {
    return statusCodes_.size();
  }
  /**
   * <code>repeated string statusCodes = 2;</code>
   * @param index The index of the element to return.
   * @return The statusCodes at the given index.
   */
  public java.lang.String getStatusCodes(int index) {
    return statusCodes_.get(index);
  }
  /**
   * <code>repeated string statusCodes = 2;</code>
   * @param index The index of the value to return.
   * @return The bytes of the statusCodes at the given index.
   */
  public com.google.protobuf.ByteString
      getStatusCodesBytes(int index) {
    return statusCodes_.getByteString(index);
  }

  private byte memoizedIsInitialized = -1;
  @java.lang.Override
  public final boolean isInitialized() {
    byte isInitialized = memoizedIsInitialized;
    if (isInitialized == 1) return true;
    if (isInitialized == 0) return false;

    memoizedIsInitialized = 1;
    return true;
  }

  @java.lang.Override
  public void writeTo(com.google.protobuf.CodedOutputStream output)
                      throws java.io.IOException {
    if (count_ != 0) {
      output.writeUInt32(1, count_);
    }
    for (int i = 0; i < statusCodes_.size(); i++) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 2, statusCodes_.getRaw(i));
    }
    unknownFields.writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (count_ != 0) {
      size += com.google.protobuf.CodedOutputStream
        .computeUInt32Size(1, count_);
    }
    {
      int dataSize = 0;
      for (int i = 0; i < statusCodes_.size(); i++) {
        dataSize += computeStringSizeNoTag(statusCodes_.getRaw(i));
      }
      size += dataSize;
      size += 1 * getStatusCodesList().size();
    }
    size += unknownFields.getSerializedSize();
    memoizedSize = size;
    return size;
  }

  @java.lang.Override
  public boolean equals(final java.lang.Object obj) {
    if (obj == this) {
     return true;
    }
    if (!(obj instanceof org.wso2.apk.enforcer.discovery.api.RetryConfig)) {
      return super.equals(obj);
    }
    org.wso2.apk.enforcer.discovery.api.RetryConfig other = (org.wso2.apk.enforcer.discovery.api.RetryConfig) obj;

    if (getCount()
        != other.getCount()) return false;
    if (!getStatusCodesList()
        .equals(other.getStatusCodesList())) return false;
    if (!unknownFields.equals(other.unknownFields)) return false;
    return true;
  }

  @java.lang.Override
  public int hashCode() {
    if (memoizedHashCode != 0) {
      return memoizedHashCode;
    }
    int hash = 41;
    hash = (19 * hash) + getDescriptor().hashCode();
    hash = (37 * hash) + COUNT_FIELD_NUMBER;
    hash = (53 * hash) + getCount();
    if (getStatusCodesCount() > 0) {
      hash = (37 * hash) + STATUSCODES_FIELD_NUMBER;
      hash = (53 * hash) + getStatusCodesList().hashCode();
    }
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static org.wso2.apk.enforcer.discovery.api.RetryConfig parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  @java.lang.Override
  public Builder newBuilderForType() { return newBuilder(); }
  public static Builder newBuilder() {
    return DEFAULT_INSTANCE.toBuilder();
  }
  public static Builder newBuilder(org.wso2.apk.enforcer.discovery.api.RetryConfig prototype) {
    return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
  }
  @java.lang.Override
  public Builder toBuilder() {
    return this == DEFAULT_INSTANCE
        ? new Builder() : new Builder().mergeFrom(this);
  }

  @java.lang.Override
  protected Builder newBuilderForType(
      com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
    Builder builder = new Builder(parent);
    return builder;
  }
  /**
   * Protobuf type {@code wso2.discovery.api.RetryConfig}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:wso2.discovery.api.RetryConfig)
      org.wso2.apk.enforcer.discovery.api.RetryConfigOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return org.wso2.apk.enforcer.discovery.api.EndpointClusterProto.internal_static_wso2_discovery_api_RetryConfig_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return org.wso2.apk.enforcer.discovery.api.EndpointClusterProto.internal_static_wso2_discovery_api_RetryConfig_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              org.wso2.apk.enforcer.discovery.api.RetryConfig.class, org.wso2.apk.enforcer.discovery.api.RetryConfig.Builder.class);
    }

    // Construct using org.wso2.apk.enforcer.discovery.api.RetryConfig.newBuilder()
    private Builder() {
      maybeForceBuilderInitialization();
    }

    private Builder(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      super(parent);
      maybeForceBuilderInitialization();
    }
    private void maybeForceBuilderInitialization() {
      if (com.google.protobuf.GeneratedMessageV3
              .alwaysUseFieldBuilders) {
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      count_ = 0;

      statusCodes_ = com.google.protobuf.LazyStringArrayList.EMPTY;
      bitField0_ = (bitField0_ & ~0x00000001);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return org.wso2.apk.enforcer.discovery.api.EndpointClusterProto.internal_static_wso2_discovery_api_RetryConfig_descriptor;
    }

    @java.lang.Override
    public org.wso2.apk.enforcer.discovery.api.RetryConfig getDefaultInstanceForType() {
      return org.wso2.apk.enforcer.discovery.api.RetryConfig.getDefaultInstance();
    }

    @java.lang.Override
    public org.wso2.apk.enforcer.discovery.api.RetryConfig build() {
      org.wso2.apk.enforcer.discovery.api.RetryConfig result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public org.wso2.apk.enforcer.discovery.api.RetryConfig buildPartial() {
      org.wso2.apk.enforcer.discovery.api.RetryConfig result = new org.wso2.apk.enforcer.discovery.api.RetryConfig(this);
      int from_bitField0_ = bitField0_;
      result.count_ = count_;
      if (((bitField0_ & 0x00000001) != 0)) {
        statusCodes_ = statusCodes_.getUnmodifiableView();
        bitField0_ = (bitField0_ & ~0x00000001);
      }
      result.statusCodes_ = statusCodes_;
      onBuilt();
      return result;
    }

    @java.lang.Override
    public Builder clone() {
      return super.clone();
    }
    @java.lang.Override
    public Builder setField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.setField(field, value);
    }
    @java.lang.Override
    public Builder clearField(
        com.google.protobuf.Descriptors.FieldDescriptor field) {
      return super.clearField(field);
    }
    @java.lang.Override
    public Builder clearOneof(
        com.google.protobuf.Descriptors.OneofDescriptor oneof) {
      return super.clearOneof(oneof);
    }
    @java.lang.Override
    public Builder setRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        int index, java.lang.Object value) {
      return super.setRepeatedField(field, index, value);
    }
    @java.lang.Override
    public Builder addRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.addRepeatedField(field, value);
    }
    @java.lang.Override
    public Builder mergeFrom(com.google.protobuf.Message other) {
      if (other instanceof org.wso2.apk.enforcer.discovery.api.RetryConfig) {
        return mergeFrom((org.wso2.apk.enforcer.discovery.api.RetryConfig)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(org.wso2.apk.enforcer.discovery.api.RetryConfig other) {
      if (other == org.wso2.apk.enforcer.discovery.api.RetryConfig.getDefaultInstance()) return this;
      if (other.getCount() != 0) {
        setCount(other.getCount());
      }
      if (!other.statusCodes_.isEmpty()) {
        if (statusCodes_.isEmpty()) {
          statusCodes_ = other.statusCodes_;
          bitField0_ = (bitField0_ & ~0x00000001);
        } else {
          ensureStatusCodesIsMutable();
          statusCodes_.addAll(other.statusCodes_);
        }
        onChanged();
      }
      this.mergeUnknownFields(other.unknownFields);
      onChanged();
      return this;
    }

    @java.lang.Override
    public final boolean isInitialized() {
      return true;
    }

    @java.lang.Override
    public Builder mergeFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      org.wso2.apk.enforcer.discovery.api.RetryConfig parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (org.wso2.apk.enforcer.discovery.api.RetryConfig) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }
    private int bitField0_;

    private int count_ ;
    /**
     * <code>uint32 count = 1;</code>
     * @return The count.
     */
    @java.lang.Override
    public int getCount() {
      return count_;
    }
    /**
     * <code>uint32 count = 1;</code>
     * @param value The count to set.
     * @return This builder for chaining.
     */
    public Builder setCount(int value) {
      
      count_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>uint32 count = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearCount() {
      
      count_ = 0;
      onChanged();
      return this;
    }

    private com.google.protobuf.LazyStringList statusCodes_ = com.google.protobuf.LazyStringArrayList.EMPTY;
    private void ensureStatusCodesIsMutable() {
      if (!((bitField0_ & 0x00000001) != 0)) {
        statusCodes_ = new com.google.protobuf.LazyStringArrayList(statusCodes_);
        bitField0_ |= 0x00000001;
       }
    }
    /**
     * <code>repeated string statusCodes = 2;</code>
     * @return A list containing the statusCodes.
     */
    public com.google.protobuf.ProtocolStringList
        getStatusCodesList() {
      return statusCodes_.getUnmodifiableView();
    }
    /**
     * <code>repeated string statusCodes = 2;</code>
     * @return The count of statusCodes.
     */
    public int getStatusCodesCount() {
      return statusCodes_.size();
    }
    /**
     * <code>repeated string statusCodes = 2;</code>
     * @param index The index of the element to return.
     * @return The statusCodes at the given index.
     */
    public java.lang.String getStatusCodes(int index) {
      return statusCodes_.get(index);
    }
    /**
     * <code>repeated string statusCodes = 2;</code>
     * @param index The index of the value to return.
     * @return The bytes of the statusCodes at the given index.
     */
    public com.google.protobuf.ByteString
        getStatusCodesBytes(int index) {
      return statusCodes_.getByteString(index);
    }
    /**
     * <code>repeated string statusCodes = 2;</code>
     * @param index The index to set the value at.
     * @param value The statusCodes to set.
     * @return This builder for chaining.
     */
    public Builder setStatusCodes(
        int index, java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  ensureStatusCodesIsMutable();
      statusCodes_.set(index, value);
      onChanged();
      return this;
    }
    /**
     * <code>repeated string statusCodes = 2;</code>
     * @param value The statusCodes to add.
     * @return This builder for chaining.
     */
    public Builder addStatusCodes(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  ensureStatusCodesIsMutable();
      statusCodes_.add(value);
      onChanged();
      return this;
    }
    /**
     * <code>repeated string statusCodes = 2;</code>
     * @param values The statusCodes to add.
     * @return This builder for chaining.
     */
    public Builder addAllStatusCodes(
        java.lang.Iterable<java.lang.String> values) {
      ensureStatusCodesIsMutable();
      com.google.protobuf.AbstractMessageLite.Builder.addAll(
          values, statusCodes_);
      onChanged();
      return this;
    }
    /**
     * <code>repeated string statusCodes = 2;</code>
     * @return This builder for chaining.
     */
    public Builder clearStatusCodes() {
      statusCodes_ = com.google.protobuf.LazyStringArrayList.EMPTY;
      bitField0_ = (bitField0_ & ~0x00000001);
      onChanged();
      return this;
    }
    /**
     * <code>repeated string statusCodes = 2;</code>
     * @param value The bytes of the statusCodes to add.
     * @return This builder for chaining.
     */
    public Builder addStatusCodesBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      ensureStatusCodesIsMutable();
      statusCodes_.add(value);
      onChanged();
      return this;
    }
    @java.lang.Override
    public final Builder setUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.setUnknownFields(unknownFields);
    }

    @java.lang.Override
    public final Builder mergeUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.mergeUnknownFields(unknownFields);
    }


    // @@protoc_insertion_point(builder_scope:wso2.discovery.api.RetryConfig)
  }

  // @@protoc_insertion_point(class_scope:wso2.discovery.api.RetryConfig)
  private static final org.wso2.apk.enforcer.discovery.api.RetryConfig DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new org.wso2.apk.enforcer.discovery.api.RetryConfig();
  }

  public static org.wso2.apk.enforcer.discovery.api.RetryConfig getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<RetryConfig>
      PARSER = new com.google.protobuf.AbstractParser<RetryConfig>() {
    @java.lang.Override
    public RetryConfig parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new RetryConfig(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<RetryConfig> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<RetryConfig> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public org.wso2.apk.enforcer.discovery.api.RetryConfig getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

