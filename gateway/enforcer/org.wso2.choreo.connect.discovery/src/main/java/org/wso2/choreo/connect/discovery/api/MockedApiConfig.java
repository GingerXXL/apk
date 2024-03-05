// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wso2/discovery/api/mocked_api_config.proto

package org.wso2.choreo.connect.discovery.api;

/**
 * <pre>
 * MockedApiConfig holds configurations defined for a mocked API operation result
 * </pre>
 *
 * Protobuf type {@code wso2.discovery.api.MockedApiConfig}
 */
public final class MockedApiConfig extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:wso2.discovery.api.MockedApiConfig)
    MockedApiConfigOrBuilder {
private static final long serialVersionUID = 0L;
  // Use MockedApiConfig.newBuilder() to construct.
  private MockedApiConfig(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private MockedApiConfig() {
    responses_ = java.util.Collections.emptyList();
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new MockedApiConfig();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private MockedApiConfig(
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
          case 26: {
            if (!((mutable_bitField0_ & 0x00000001) != 0)) {
              responses_ = new java.util.ArrayList<org.wso2.choreo.connect.discovery.api.MockedResponseConfig>();
              mutable_bitField0_ |= 0x00000001;
            }
            responses_.add(
                input.readMessage(org.wso2.choreo.connect.discovery.api.MockedResponseConfig.parser(), extensionRegistry));
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
        responses_ = java.util.Collections.unmodifiableList(responses_);
      }
      this.unknownFields = unknownFields.build();
      makeExtensionsImmutable();
    }
  }
  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return org.wso2.choreo.connect.discovery.api.MockedApiConfigProto.internal_static_wso2_discovery_api_MockedApiConfig_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return org.wso2.choreo.connect.discovery.api.MockedApiConfigProto.internal_static_wso2_discovery_api_MockedApiConfig_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            org.wso2.choreo.connect.discovery.api.MockedApiConfig.class, org.wso2.choreo.connect.discovery.api.MockedApiConfig.Builder.class);
  }

  public static final int RESPONSES_FIELD_NUMBER = 3;
  private java.util.List<org.wso2.choreo.connect.discovery.api.MockedResponseConfig> responses_;
  /**
   * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
   */
  @java.lang.Override
  public java.util.List<org.wso2.choreo.connect.discovery.api.MockedResponseConfig> getResponsesList() {
    return responses_;
  }
  /**
   * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
   */
  @java.lang.Override
  public java.util.List<? extends org.wso2.choreo.connect.discovery.api.MockedResponseConfigOrBuilder> 
      getResponsesOrBuilderList() {
    return responses_;
  }
  /**
   * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
   */
  @java.lang.Override
  public int getResponsesCount() {
    return responses_.size();
  }
  /**
   * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
   */
  @java.lang.Override
  public org.wso2.choreo.connect.discovery.api.MockedResponseConfig getResponses(int index) {
    return responses_.get(index);
  }
  /**
   * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
   */
  @java.lang.Override
  public org.wso2.choreo.connect.discovery.api.MockedResponseConfigOrBuilder getResponsesOrBuilder(
      int index) {
    return responses_.get(index);
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
    for (int i = 0; i < responses_.size(); i++) {
      output.writeMessage(3, responses_.get(i));
    }
    unknownFields.writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    for (int i = 0; i < responses_.size(); i++) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(3, responses_.get(i));
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
    if (!(obj instanceof org.wso2.choreo.connect.discovery.api.MockedApiConfig)) {
      return super.equals(obj);
    }
    org.wso2.choreo.connect.discovery.api.MockedApiConfig other = (org.wso2.choreo.connect.discovery.api.MockedApiConfig) obj;

    if (!getResponsesList()
        .equals(other.getResponsesList())) return false;
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
    if (getResponsesCount() > 0) {
      hash = (37 * hash) + RESPONSES_FIELD_NUMBER;
      hash = (53 * hash) + getResponsesList().hashCode();
    }
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig parseFrom(
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
  public static Builder newBuilder(org.wso2.choreo.connect.discovery.api.MockedApiConfig prototype) {
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
   * <pre>
   * MockedApiConfig holds configurations defined for a mocked API operation result
   * </pre>
   *
   * Protobuf type {@code wso2.discovery.api.MockedApiConfig}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:wso2.discovery.api.MockedApiConfig)
      org.wso2.choreo.connect.discovery.api.MockedApiConfigOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return org.wso2.choreo.connect.discovery.api.MockedApiConfigProto.internal_static_wso2_discovery_api_MockedApiConfig_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return org.wso2.choreo.connect.discovery.api.MockedApiConfigProto.internal_static_wso2_discovery_api_MockedApiConfig_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              org.wso2.choreo.connect.discovery.api.MockedApiConfig.class, org.wso2.choreo.connect.discovery.api.MockedApiConfig.Builder.class);
    }

    // Construct using org.wso2.choreo.connect.discovery.api.MockedApiConfig.newBuilder()
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
        getResponsesFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      if (responsesBuilder_ == null) {
        responses_ = java.util.Collections.emptyList();
        bitField0_ = (bitField0_ & ~0x00000001);
      } else {
        responsesBuilder_.clear();
      }
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return org.wso2.choreo.connect.discovery.api.MockedApiConfigProto.internal_static_wso2_discovery_api_MockedApiConfig_descriptor;
    }

    @java.lang.Override
    public org.wso2.choreo.connect.discovery.api.MockedApiConfig getDefaultInstanceForType() {
      return org.wso2.choreo.connect.discovery.api.MockedApiConfig.getDefaultInstance();
    }

    @java.lang.Override
    public org.wso2.choreo.connect.discovery.api.MockedApiConfig build() {
      org.wso2.choreo.connect.discovery.api.MockedApiConfig result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public org.wso2.choreo.connect.discovery.api.MockedApiConfig buildPartial() {
      org.wso2.choreo.connect.discovery.api.MockedApiConfig result = new org.wso2.choreo.connect.discovery.api.MockedApiConfig(this);
      int from_bitField0_ = bitField0_;
      if (responsesBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0)) {
          responses_ = java.util.Collections.unmodifiableList(responses_);
          bitField0_ = (bitField0_ & ~0x00000001);
        }
        result.responses_ = responses_;
      } else {
        result.responses_ = responsesBuilder_.build();
      }
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
      if (other instanceof org.wso2.choreo.connect.discovery.api.MockedApiConfig) {
        return mergeFrom((org.wso2.choreo.connect.discovery.api.MockedApiConfig)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(org.wso2.choreo.connect.discovery.api.MockedApiConfig other) {
      if (other == org.wso2.choreo.connect.discovery.api.MockedApiConfig.getDefaultInstance()) return this;
      if (responsesBuilder_ == null) {
        if (!other.responses_.isEmpty()) {
          if (responses_.isEmpty()) {
            responses_ = other.responses_;
            bitField0_ = (bitField0_ & ~0x00000001);
          } else {
            ensureResponsesIsMutable();
            responses_.addAll(other.responses_);
          }
          onChanged();
        }
      } else {
        if (!other.responses_.isEmpty()) {
          if (responsesBuilder_.isEmpty()) {
            responsesBuilder_.dispose();
            responsesBuilder_ = null;
            responses_ = other.responses_;
            bitField0_ = (bitField0_ & ~0x00000001);
            responsesBuilder_ = 
              com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders ?
                 getResponsesFieldBuilder() : null;
          } else {
            responsesBuilder_.addAllMessages(other.responses_);
          }
        }
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
      org.wso2.choreo.connect.discovery.api.MockedApiConfig parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (org.wso2.choreo.connect.discovery.api.MockedApiConfig) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }
    private int bitField0_;

    private java.util.List<org.wso2.choreo.connect.discovery.api.MockedResponseConfig> responses_ =
      java.util.Collections.emptyList();
    private void ensureResponsesIsMutable() {
      if (!((bitField0_ & 0x00000001) != 0)) {
        responses_ = new java.util.ArrayList<org.wso2.choreo.connect.discovery.api.MockedResponseConfig>(responses_);
        bitField0_ |= 0x00000001;
       }
    }

    private com.google.protobuf.RepeatedFieldBuilderV3<
        org.wso2.choreo.connect.discovery.api.MockedResponseConfig, org.wso2.choreo.connect.discovery.api.MockedResponseConfig.Builder, org.wso2.choreo.connect.discovery.api.MockedResponseConfigOrBuilder> responsesBuilder_;

    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public java.util.List<org.wso2.choreo.connect.discovery.api.MockedResponseConfig> getResponsesList() {
      if (responsesBuilder_ == null) {
        return java.util.Collections.unmodifiableList(responses_);
      } else {
        return responsesBuilder_.getMessageList();
      }
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public int getResponsesCount() {
      if (responsesBuilder_ == null) {
        return responses_.size();
      } else {
        return responsesBuilder_.getCount();
      }
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public org.wso2.choreo.connect.discovery.api.MockedResponseConfig getResponses(int index) {
      if (responsesBuilder_ == null) {
        return responses_.get(index);
      } else {
        return responsesBuilder_.getMessage(index);
      }
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public Builder setResponses(
        int index, org.wso2.choreo.connect.discovery.api.MockedResponseConfig value) {
      if (responsesBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureResponsesIsMutable();
        responses_.set(index, value);
        onChanged();
      } else {
        responsesBuilder_.setMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public Builder setResponses(
        int index, org.wso2.choreo.connect.discovery.api.MockedResponseConfig.Builder builderForValue) {
      if (responsesBuilder_ == null) {
        ensureResponsesIsMutable();
        responses_.set(index, builderForValue.build());
        onChanged();
      } else {
        responsesBuilder_.setMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public Builder addResponses(org.wso2.choreo.connect.discovery.api.MockedResponseConfig value) {
      if (responsesBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureResponsesIsMutable();
        responses_.add(value);
        onChanged();
      } else {
        responsesBuilder_.addMessage(value);
      }
      return this;
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public Builder addResponses(
        int index, org.wso2.choreo.connect.discovery.api.MockedResponseConfig value) {
      if (responsesBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureResponsesIsMutable();
        responses_.add(index, value);
        onChanged();
      } else {
        responsesBuilder_.addMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public Builder addResponses(
        org.wso2.choreo.connect.discovery.api.MockedResponseConfig.Builder builderForValue) {
      if (responsesBuilder_ == null) {
        ensureResponsesIsMutable();
        responses_.add(builderForValue.build());
        onChanged();
      } else {
        responsesBuilder_.addMessage(builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public Builder addResponses(
        int index, org.wso2.choreo.connect.discovery.api.MockedResponseConfig.Builder builderForValue) {
      if (responsesBuilder_ == null) {
        ensureResponsesIsMutable();
        responses_.add(index, builderForValue.build());
        onChanged();
      } else {
        responsesBuilder_.addMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public Builder addAllResponses(
        java.lang.Iterable<? extends org.wso2.choreo.connect.discovery.api.MockedResponseConfig> values) {
      if (responsesBuilder_ == null) {
        ensureResponsesIsMutable();
        com.google.protobuf.AbstractMessageLite.Builder.addAll(
            values, responses_);
        onChanged();
      } else {
        responsesBuilder_.addAllMessages(values);
      }
      return this;
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public Builder clearResponses() {
      if (responsesBuilder_ == null) {
        responses_ = java.util.Collections.emptyList();
        bitField0_ = (bitField0_ & ~0x00000001);
        onChanged();
      } else {
        responsesBuilder_.clear();
      }
      return this;
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public Builder removeResponses(int index) {
      if (responsesBuilder_ == null) {
        ensureResponsesIsMutable();
        responses_.remove(index);
        onChanged();
      } else {
        responsesBuilder_.remove(index);
      }
      return this;
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public org.wso2.choreo.connect.discovery.api.MockedResponseConfig.Builder getResponsesBuilder(
        int index) {
      return getResponsesFieldBuilder().getBuilder(index);
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public org.wso2.choreo.connect.discovery.api.MockedResponseConfigOrBuilder getResponsesOrBuilder(
        int index) {
      if (responsesBuilder_ == null) {
        return responses_.get(index);  } else {
        return responsesBuilder_.getMessageOrBuilder(index);
      }
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public java.util.List<? extends org.wso2.choreo.connect.discovery.api.MockedResponseConfigOrBuilder> 
         getResponsesOrBuilderList() {
      if (responsesBuilder_ != null) {
        return responsesBuilder_.getMessageOrBuilderList();
      } else {
        return java.util.Collections.unmodifiableList(responses_);
      }
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public org.wso2.choreo.connect.discovery.api.MockedResponseConfig.Builder addResponsesBuilder() {
      return getResponsesFieldBuilder().addBuilder(
          org.wso2.choreo.connect.discovery.api.MockedResponseConfig.getDefaultInstance());
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public org.wso2.choreo.connect.discovery.api.MockedResponseConfig.Builder addResponsesBuilder(
        int index) {
      return getResponsesFieldBuilder().addBuilder(
          index, org.wso2.choreo.connect.discovery.api.MockedResponseConfig.getDefaultInstance());
    }
    /**
     * <code>repeated .wso2.discovery.api.MockedResponseConfig responses = 3;</code>
     */
    public java.util.List<org.wso2.choreo.connect.discovery.api.MockedResponseConfig.Builder> 
         getResponsesBuilderList() {
      return getResponsesFieldBuilder().getBuilderList();
    }
    private com.google.protobuf.RepeatedFieldBuilderV3<
        org.wso2.choreo.connect.discovery.api.MockedResponseConfig, org.wso2.choreo.connect.discovery.api.MockedResponseConfig.Builder, org.wso2.choreo.connect.discovery.api.MockedResponseConfigOrBuilder> 
        getResponsesFieldBuilder() {
      if (responsesBuilder_ == null) {
        responsesBuilder_ = new com.google.protobuf.RepeatedFieldBuilderV3<
            org.wso2.choreo.connect.discovery.api.MockedResponseConfig, org.wso2.choreo.connect.discovery.api.MockedResponseConfig.Builder, org.wso2.choreo.connect.discovery.api.MockedResponseConfigOrBuilder>(
                responses_,
                ((bitField0_ & 0x00000001) != 0),
                getParentForChildren(),
                isClean());
        responses_ = null;
      }
      return responsesBuilder_;
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


    // @@protoc_insertion_point(builder_scope:wso2.discovery.api.MockedApiConfig)
  }

  // @@protoc_insertion_point(class_scope:wso2.discovery.api.MockedApiConfig)
  private static final org.wso2.choreo.connect.discovery.api.MockedApiConfig DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new org.wso2.choreo.connect.discovery.api.MockedApiConfig();
  }

  public static org.wso2.choreo.connect.discovery.api.MockedApiConfig getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<MockedApiConfig>
      PARSER = new com.google.protobuf.AbstractParser<MockedApiConfig>() {
    @java.lang.Override
    public MockedApiConfig parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new MockedApiConfig(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<MockedApiConfig> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<MockedApiConfig> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public org.wso2.choreo.connect.discovery.api.MockedApiConfig getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}
