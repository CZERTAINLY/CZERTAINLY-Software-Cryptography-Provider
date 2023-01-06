package com.czertainly.cp.soft.attribute;

import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.BooleanAttributeContent;
import com.czertainly.api.model.common.attribute.v2.properties.DataAttributeProperties;
import com.czertainly.cp.soft.collection.DilithiumLevel;

import java.util.List;

public class DilithiumKeyAttributes {

    // Falcon Attributes
    public static final String ATTRIBUTE_DATA_DILITIHIUM_LEVEL = "data_dilitihiumLevel";
    public static final String ATTRIBUTE_DATA_DILITIHIUM_LEVEL_UUID = "88a0fa46-dcdd-4d29-a51c-e563e21c9872";
    public static final String ATTRIBUTE_DATA_DILITIHIUM_LEVEL_LABEL = "Dilithium NIST Security Level";
    public static final String ATTRIBUTE_DATA_DILITIHIUM_LEVEL_DESCRIPTION = "Security strength according NIST definition in PQC contest";

    public static final String ATTRIBUTE_DATA_DILITIHIUM_USE_AES = "data_dilitihiumUseAes";
    public static final String ATTRIBUTE_DATA_DILITIHIUM_USE_AES_UUID = "275f094b-f903-4afd-9528-43f017d81e04";
    public static final String ATTRIBUTE_DATA_DILITIHIUM_USE_AES_LABEL = "Use AES-256 for expansion";
    public static final String ATTRIBUTE_DATA_DILITIHIUM_USE_AES_DESCRIPTION = "Use AES-256 in counter mode instead of SHAKE to expand the matrix and the masking vectors, and to sample the secret polynomials";

    public static List<BaseAttribute> getDilithiumKeySpecAttributes() {
        return List.of(
                buildDataDilithiumLevel(),
                buildDataDilithiumUseAes()
        );
    }

    public static BaseAttribute buildDataDilithiumLevel() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_DILITIHIUM_LEVEL_UUID);
        attribute.setName(ATTRIBUTE_DATA_DILITIHIUM_LEVEL);
        attribute.setDescription(ATTRIBUTE_DATA_DILITIHIUM_LEVEL_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.INTEGER);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_DILITIHIUM_LEVEL_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(DilithiumLevel.asIntegerAttributeContentList());

        return attribute;
    }

    public static BaseAttribute buildDataDilithiumUseAes() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_DILITIHIUM_USE_AES_UUID);
        attribute.setName(ATTRIBUTE_DATA_DILITIHIUM_USE_AES);
        attribute.setDescription(ATTRIBUTE_DATA_DILITIHIUM_USE_AES_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.BOOLEAN);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_DILITIHIUM_USE_AES_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(false);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(List.of(new BooleanAttributeContent(false)));

        return attribute;
    }

}
