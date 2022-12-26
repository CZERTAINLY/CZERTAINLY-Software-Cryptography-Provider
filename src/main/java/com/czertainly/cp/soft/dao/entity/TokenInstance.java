package com.czertainly.cp.soft.dao.entity;

import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.Base64;
import java.util.List;

@Entity
@Table(name = "token_instance")
public class TokenInstance extends UniquelyIdentified {

    @Column(name = "name")
    private String name;

    @Column(name = "data")
    private String data;

    @Column(name = "attributes")
    private String attributes;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public byte[] getData() {
        return Base64.getDecoder().decode(data);
    }

    public void setData(byte[] data) {
        this.data = Base64.getEncoder().encodeToString(data);
    }

    public List<BaseAttribute> getAttributes() {
        return AttributeDefinitionUtils.deserialize(attributes, BaseAttribute.class);
    }

    public void setAttributes(List<BaseAttribute> attributes) {
        this.attributes = AttributeDefinitionUtils.serialize(attributes);;
    }

    public TokenInstanceDto mapToDto() {
        TokenInstanceDto dto = new TokenInstanceDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);

        if (attributes != null) {
            dto.setAttributes(this.getAttributes());
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
