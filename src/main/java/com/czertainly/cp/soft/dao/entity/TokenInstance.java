package com.czertainly.cp.soft.dao.entity;

import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.util.SecretEncodingVersion;
import com.czertainly.cp.soft.util.SecretsUtil;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.sql.Timestamp;
import java.util.Base64;
import java.util.List;

@Entity
@Table(name = "token_instance")
public class TokenInstance extends UniquelyIdentified {

    @Column(name = "name")
    private String name;

    @Column(name = "code")
    private String code;

    @Column(name = "data")
    private String data;

    @Column(name = "metadata")
    private String metadata;

    @Column(name = "timestamp")
    @Version
    private Timestamp timestamp;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCode() {
        if (code != null) {
            return SecretsUtil.decodeAndDecryptSecretString(code, SecretEncodingVersion.V1);
        }
        return null;
    }

    public void setCode(String code) {
        if (code != null) {
            this.code = SecretsUtil.encryptAndEncodeSecretString(code, SecretEncodingVersion.V1);
        } else {
            this.code = null;
        }
    }

    public byte[] getData() {
        return Base64.getDecoder().decode(data);
    }

    public void setData(byte[] data) {
        this.data = Base64.getEncoder().encodeToString(data);
    }

    public List<MetadataAttribute> getMetadata() {
        return AttributeDefinitionUtils.deserialize(metadata, MetadataAttribute.class);
    }

    public void setMetadata(List<MetadataAttribute> metadata) {
        this.metadata = AttributeDefinitionUtils.serialize(metadata);
    }

    public TokenInstanceDto mapToDto() {
        TokenInstanceDto dto = new TokenInstanceDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);

        if (metadata != null) {
            dto.setMetadata(getMetadata());
        }

        return dto;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenInstance that = (TokenInstance) o;
        return new EqualsBuilder().append(uuid, that.uuid).isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(uuid).toHashCode();
    }

}
