package com.czertainly.cp.soft.dao.entity;

import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.czertainly.api.model.connector.cryptography.key.value.*;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.util.KeyUtil;
import jakarta.persistence.*;
import jakarta.persistence.criteria.CriteriaBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "key_data")
public class KeyData extends UniquelyIdentified {

    @Column(name = "name")
    private String name;

    @Column(name = "association")
    private String association;

    @Column(name = "type")
    private KeyType type;

    @Column(name = "algorithm")
    private KeyAlgorithm algorithm;

    @Column(name = "format")
    private KeyFormat format;

    @Column(name = "value", length = Integer.MAX_VALUE)
    private String value;

    @Column(name = "length")
    private int length;

    @Column(name = "metadata", length = Integer.MAX_VALUE)
    private String metadata;

    @ManyToOne()
    @JoinColumn(name = "token_instance_uuid", insertable = false, updatable = false)
    private TokenInstance tokenInstance;

    @Column(name = "token_instance_uuid")
    private UUID tokenInstanceUuid;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAssociation() {
        return association;
    }

    public void setAssociation(String association) {
        this.association = association;
    }

    public KeyType getType() {
        return type;
    }

    public void setType(KeyType type) {
        this.type = type;
    }

    public KeyAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(KeyAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public KeyFormat getFormat() {
        return format;
    }

    public void setFormat(KeyFormat format) {
        this.format = format;
    }

    public KeyValue getValue() {
        switch (format) {
            case RAW:
                return KeyUtil.deserializeKeyValue(value, RawKeyValue.class);
            case SPKI:
                return KeyUtil.deserializeKeyValue(value, SpkiKeyValue.class);
            case PRKI:
                return KeyUtil.deserializeKeyValue(value, PrkiKeyValue.class);
            case EPRKI:
                return KeyUtil.deserializeKeyValue(value, EprkiKeyValue.class);
            case CUSTOM:
                return KeyUtil.deserializeKeyValue(value, CustomKeyValue.class);
            default:
                throw new IllegalArgumentException("Unsupported key format: " + format);
        }
    }

    public void setValue(KeyValue value) {
        this.value = KeyUtil.serializeKeyValue(value);
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public List<MetadataAttribute> getMetadata() {
        return AttributeDefinitionUtils.deserialize(metadata, MetadataAttribute.class);
    }

    public void setMetadata(List<MetadataAttribute> metadata) {
        this.metadata = AttributeDefinitionUtils.serialize(metadata);
    }

    public TokenInstance getTokenInstance() {
        return tokenInstance;
    }

    public void setTokenInstance(TokenInstance tokenInstance) {
        this.tokenInstance = tokenInstance;
        if(tokenInstance != null) this.tokenInstanceUuid = tokenInstance.getUuid();
        else this.tokenInstanceUuid = null;
    }

    public UUID getTokenInstanceUuid() {
        return tokenInstanceUuid;
    }

    public void setTokenInstanceUuid(UUID tokenInstanceUuid) {
        this.tokenInstanceUuid = tokenInstanceUuid;
    }

    public com.czertainly.api.model.connector.cryptography.key.KeyData toKeyData() {
        com.czertainly.api.model.connector.cryptography.key.KeyData keyData = new com.czertainly.api.model.connector.cryptography.key.KeyData();
        keyData.setType(getType());
        keyData.setAlgorithm(getAlgorithm());
        keyData.setFormat(getFormat());
        keyData.setValue(getValue());
        keyData.setLength(getLength());
        keyData.setMetadata(getMetadata());

        return keyData;
    }

    public KeyDataResponseDto toKeyDataResponseDto() {
        com.czertainly.api.model.connector.cryptography.key.KeyData keyData = toKeyData();

        KeyDataResponseDto keyDataResponseDto = new KeyDataResponseDto();
        keyDataResponseDto.setUuid(getUuid().toString());
        keyDataResponseDto.setName(getName());
        keyDataResponseDto.setAssociation(getAssociation());
        keyDataResponseDto.setKeyData(keyData);

        return keyDataResponseDto;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyData that = (KeyData) o;
        return new EqualsBuilder().append(uuid, that.uuid).isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(uuid).toHashCode();
    }
}
