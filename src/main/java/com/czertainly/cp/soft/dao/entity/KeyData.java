package com.czertainly.cp.soft.dao.entity;

import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.connector.cryptography.enums.CryptographicAlgorithm;
import com.czertainly.api.model.connector.cryptography.enums.KeyFormat;
import com.czertainly.api.model.connector.cryptography.enums.KeyType;
import com.czertainly.core.util.AttributeDefinitionUtils;
import jakarta.persistence.*;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "key_data")
public class KeyData extends UniquelyIdentified {

    @Column(name = "name")
    private String name;

    @Column(name = "type")
    private KeyType type;

    @Column(name = "algorithm")
    private CryptographicAlgorithm algorithm;

    @Column(name = "format")
    private KeyFormat format;

    @Column(name = "value")
    private String value;

    @Column(name = "length")
    private int length;

    @Column(name = "metadata")
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

    public KeyType getType() {
        return type;
    }

    public void setType(KeyType type) {
        this.type = type;
    }

    public CryptographicAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(CryptographicAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public KeyFormat getFormat() {
        return format;
    }

    public void setFormat(KeyFormat format) {
        this.format = format;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
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
