// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wso2/discovery/keymgt/key_manager_config.proto

package org.wso2.choreo.connect.discovery.keymgt;

/**
 * <pre>
 * KeyManagerConfig model
 * </pre>
 *
 * Protobuf type {@code wso2.discovery.keymgt.KeyManagerConfig}
 */
public final class KeyManagerConfig extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:wso2.discovery.keymgt.KeyManagerConfig)
    KeyManagerConfigOrBuilder {
private static final long serialVersionUID = 0L;
  // Use KeyManagerConfig.newBuilder() to construct.
  private KeyManagerConfig(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private KeyManagerConfig() {
    name_ = "";
    type_ = "";
    tenantDomain_ = "";
    configuration_ = "";
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new KeyManagerConfig();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private KeyManagerConfig(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    this();
    if (extensionRegistry == null) {
      throw new java.lang.NullPointerException();
    }
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
          case 10: {
            java.lang.String s = input.readStringRequireUtf8();

            name_ = s;
            break;
          }
          case 18: {
            java.lang.String s = input.readStringRequireUtf8();

            type_ = s;
            break;
          }
          case 24: {

            enabled_ = input.readBool();
            break;
          }
          case 34: {
            java.lang.String s = input.readStringRequireUtf8();

            tenantDomain_ = s;
            break;
          }
          case 42: {
            java.lang.String s = input.readStringRequireUtf8();

            configuration_ = s;
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
      this.unknownFields = unknownFields.build();
      makeExtensionsImmutable();
    }
  }
  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfigProto.internal_static_wso2_discovery_keymgt_KeyManagerConfig_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfigProto.internal_static_wso2_discovery_keymgt_KeyManagerConfig_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig.class, org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig.Builder.class);
  }

  public static final int NAME_FIELD_NUMBER = 1;
  private volatile java.lang.Object name_;
  /**
   * <code>string name = 1;</code>
   * @return The name.
   */
  @java.lang.Override
  public java.lang.String getName() {
    java.lang.Object ref = name_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      name_ = s;
      return s;
    }
  }
  /**
   * <code>string name = 1;</code>
   * @return The bytes for name.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getNameBytes() {
    java.lang.Object ref = name_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      name_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int TYPE_FIELD_NUMBER = 2;
  private volatile java.lang.Object type_;
  /**
   * <code>string type = 2;</code>
   * @return The type.
   */
  @java.lang.Override
  public java.lang.String getType() {
    java.lang.Object ref = type_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      type_ = s;
      return s;
    }
  }
  /**
   * <code>string type = 2;</code>
   * @return The bytes for type.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getTypeBytes() {
    java.lang.Object ref = type_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      type_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int ENABLED_FIELD_NUMBER = 3;
  private boolean enabled_;
  /**
   * <code>bool enabled = 3;</code>
   * @return The enabled.
   */
  @java.lang.Override
  public boolean getEnabled() {
    return enabled_;
  }

  public static final int TENANTDOMAIN_FIELD_NUMBER = 4;
  private volatile java.lang.Object tenantDomain_;
  /**
   * <code>string tenantDomain = 4;</code>
   * @return The tenantDomain.
   */
  @java.lang.Override
  public java.lang.String getTenantDomain() {
    java.lang.Object ref = tenantDomain_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      tenantDomain_ = s;
      return s;
    }
  }
  /**
   * <code>string tenantDomain = 4;</code>
   * @return The bytes for tenantDomain.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getTenantDomainBytes() {
    java.lang.Object ref = tenantDomain_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      tenantDomain_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int CONFIGURATION_FIELD_NUMBER = 5;
  private volatile java.lang.Object configuration_;
  /**
   * <code>string configuration = 5;</code>
   * @return The configuration.
   */
  @java.lang.Override
  public java.lang.String getConfiguration() {
    java.lang.Object ref = configuration_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      configuration_ = s;
      return s;
    }
  }
  /**
   * <code>string configuration = 5;</code>
   * @return The bytes for configuration.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getConfigurationBytes() {
    java.lang.Object ref = configuration_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      configuration_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
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
    if (!getNameBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 1, name_);
    }
    if (!getTypeBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 2, type_);
    }
    if (enabled_ != false) {
      output.writeBool(3, enabled_);
    }
    if (!getTenantDomainBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 4, tenantDomain_);
    }
    if (!getConfigurationBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 5, configuration_);
    }
    unknownFields.writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (!getNameBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, name_);
    }
    if (!getTypeBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, type_);
    }
    if (enabled_ != false) {
      size += com.google.protobuf.CodedOutputStream
        .computeBoolSize(3, enabled_);
    }
    if (!getTenantDomainBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(4, tenantDomain_);
    }
    if (!getConfigurationBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(5, configuration_);
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
    if (!(obj instanceof org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig)) {
      return super.equals(obj);
    }
    org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig other = (org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig) obj;

    if (!getName()
        .equals(other.getName())) return false;
    if (!getType()
        .equals(other.getType())) return false;
    if (getEnabled()
        != other.getEnabled()) return false;
    if (!getTenantDomain()
        .equals(other.getTenantDomain())) return false;
    if (!getConfiguration()
        .equals(other.getConfiguration())) return false;
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
    hash = (37 * hash) + NAME_FIELD_NUMBER;
    hash = (53 * hash) + getName().hashCode();
    hash = (37 * hash) + TYPE_FIELD_NUMBER;
    hash = (53 * hash) + getType().hashCode();
    hash = (37 * hash) + ENABLED_FIELD_NUMBER;
    hash = (53 * hash) + com.google.protobuf.Internal.hashBoolean(
        getEnabled());
    hash = (37 * hash) + TENANTDOMAIN_FIELD_NUMBER;
    hash = (53 * hash) + getTenantDomain().hashCode();
    hash = (37 * hash) + CONFIGURATION_FIELD_NUMBER;
    hash = (53 * hash) + getConfiguration().hashCode();
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parseFrom(
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
  public static Builder newBuilder(org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig prototype) {
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
   * KeyManagerConfig model
   * </pre>
   *
   * Protobuf type {@code wso2.discovery.keymgt.KeyManagerConfig}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:wso2.discovery.keymgt.KeyManagerConfig)
      org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfigOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfigProto.internal_static_wso2_discovery_keymgt_KeyManagerConfig_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfigProto.internal_static_wso2_discovery_keymgt_KeyManagerConfig_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig.class, org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig.Builder.class);
    }

    // Construct using org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig.newBuilder()
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
      name_ = "";

      type_ = "";

      enabled_ = false;

      tenantDomain_ = "";

      configuration_ = "";

      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfigProto.internal_static_wso2_discovery_keymgt_KeyManagerConfig_descriptor;
    }

    @java.lang.Override
    public org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig getDefaultInstanceForType() {
      return org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig.getDefaultInstance();
    }

    @java.lang.Override
    public org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig build() {
      org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig buildPartial() {
      org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig result = new org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig(this);
      result.name_ = name_;
      result.type_ = type_;
      result.enabled_ = enabled_;
      result.tenantDomain_ = tenantDomain_;
      result.configuration_ = configuration_;
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
      if (other instanceof org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig) {
        return mergeFrom((org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig other) {
      if (other == org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig.getDefaultInstance()) return this;
      if (!other.getName().isEmpty()) {
        name_ = other.name_;
        onChanged();
      }
      if (!other.getType().isEmpty()) {
        type_ = other.type_;
        onChanged();
      }
      if (other.getEnabled() != false) {
        setEnabled(other.getEnabled());
      }
      if (!other.getTenantDomain().isEmpty()) {
        tenantDomain_ = other.tenantDomain_;
        onChanged();
      }
      if (!other.getConfiguration().isEmpty()) {
        configuration_ = other.configuration_;
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
      org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }

    private java.lang.Object name_ = "";
    /**
     * <code>string name = 1;</code>
     * @return The name.
     */
    public java.lang.String getName() {
      java.lang.Object ref = name_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        name_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string name = 1;</code>
     * @return The bytes for name.
     */
    public com.google.protobuf.ByteString
        getNameBytes() {
      java.lang.Object ref = name_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        name_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string name = 1;</code>
     * @param value The name to set.
     * @return This builder for chaining.
     */
    public Builder setName(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      name_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>string name = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearName() {
      
      name_ = getDefaultInstance().getName();
      onChanged();
      return this;
    }
    /**
     * <code>string name = 1;</code>
     * @param value The bytes for name to set.
     * @return This builder for chaining.
     */
    public Builder setNameBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      
      name_ = value;
      onChanged();
      return this;
    }

    private java.lang.Object type_ = "";
    /**
     * <code>string type = 2;</code>
     * @return The type.
     */
    public java.lang.String getType() {
      java.lang.Object ref = type_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        type_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string type = 2;</code>
     * @return The bytes for type.
     */
    public com.google.protobuf.ByteString
        getTypeBytes() {
      java.lang.Object ref = type_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        type_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string type = 2;</code>
     * @param value The type to set.
     * @return This builder for chaining.
     */
    public Builder setType(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      type_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>string type = 2;</code>
     * @return This builder for chaining.
     */
    public Builder clearType() {
      
      type_ = getDefaultInstance().getType();
      onChanged();
      return this;
    }
    /**
     * <code>string type = 2;</code>
     * @param value The bytes for type to set.
     * @return This builder for chaining.
     */
    public Builder setTypeBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      
      type_ = value;
      onChanged();
      return this;
    }

    private boolean enabled_ ;
    /**
     * <code>bool enabled = 3;</code>
     * @return The enabled.
     */
    @java.lang.Override
    public boolean getEnabled() {
      return enabled_;
    }
    /**
     * <code>bool enabled = 3;</code>
     * @param value The enabled to set.
     * @return This builder for chaining.
     */
    public Builder setEnabled(boolean value) {
      
      enabled_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>bool enabled = 3;</code>
     * @return This builder for chaining.
     */
    public Builder clearEnabled() {
      
      enabled_ = false;
      onChanged();
      return this;
    }

    private java.lang.Object tenantDomain_ = "";
    /**
     * <code>string tenantDomain = 4;</code>
     * @return The tenantDomain.
     */
    public java.lang.String getTenantDomain() {
      java.lang.Object ref = tenantDomain_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        tenantDomain_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string tenantDomain = 4;</code>
     * @return The bytes for tenantDomain.
     */
    public com.google.protobuf.ByteString
        getTenantDomainBytes() {
      java.lang.Object ref = tenantDomain_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        tenantDomain_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string tenantDomain = 4;</code>
     * @param value The tenantDomain to set.
     * @return This builder for chaining.
     */
    public Builder setTenantDomain(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      tenantDomain_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>string tenantDomain = 4;</code>
     * @return This builder for chaining.
     */
    public Builder clearTenantDomain() {
      
      tenantDomain_ = getDefaultInstance().getTenantDomain();
      onChanged();
      return this;
    }
    /**
     * <code>string tenantDomain = 4;</code>
     * @param value The bytes for tenantDomain to set.
     * @return This builder for chaining.
     */
    public Builder setTenantDomainBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      
      tenantDomain_ = value;
      onChanged();
      return this;
    }

    private java.lang.Object configuration_ = "";
    /**
     * <code>string configuration = 5;</code>
     * @return The configuration.
     */
    public java.lang.String getConfiguration() {
      java.lang.Object ref = configuration_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        configuration_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string configuration = 5;</code>
     * @return The bytes for configuration.
     */
    public com.google.protobuf.ByteString
        getConfigurationBytes() {
      java.lang.Object ref = configuration_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        configuration_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string configuration = 5;</code>
     * @param value The configuration to set.
     * @return This builder for chaining.
     */
    public Builder setConfiguration(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      configuration_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>string configuration = 5;</code>
     * @return This builder for chaining.
     */
    public Builder clearConfiguration() {
      
      configuration_ = getDefaultInstance().getConfiguration();
      onChanged();
      return this;
    }
    /**
     * <code>string configuration = 5;</code>
     * @param value The bytes for configuration to set.
     * @return This builder for chaining.
     */
    public Builder setConfigurationBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      
      configuration_ = value;
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


    // @@protoc_insertion_point(builder_scope:wso2.discovery.keymgt.KeyManagerConfig)
  }

  // @@protoc_insertion_point(class_scope:wso2.discovery.keymgt.KeyManagerConfig)
  private static final org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig();
  }

  public static org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<KeyManagerConfig>
      PARSER = new com.google.protobuf.AbstractParser<KeyManagerConfig>() {
    @java.lang.Override
    public KeyManagerConfig parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new KeyManagerConfig(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<KeyManagerConfig> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<KeyManagerConfig> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public org.wso2.choreo.connect.discovery.keymgt.KeyManagerConfig getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

