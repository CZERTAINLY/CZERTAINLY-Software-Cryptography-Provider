package com.czertainly.cp.soft.attribute;

import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.BooleanAttributeContent;
import com.czertainly.api.model.common.attribute.v2.properties.DataAttributeProperties;
import com.czertainly.cp.soft.collection.SphincsPlusHash;
import com.czertainly.cp.soft.collection.SphincsPlusParameterSet;

import java.util.List;

public class SphincsPlusKeyAttributes {

    // Falcon Attributes
    public static final String ATTRIBUTE_DATA_SPHINCS_HASH = "data_sphincsHash";
    public static final String ATTRIBUTE_DATA_SPHINCS_HASH_UUID = "563eeac3-68a5-4d11-8015-0a6bceb1b9c2";
    public static final String ATTRIBUTE_DATA_SPHINCS_HASH_LABEL = "Hash Function";
    public static final String ATTRIBUTE_DATA_SPHINCS_HASH_DESCRIPTION = "Hash function used to instantiate the signature scheme";

    public static final String ATTRIBUTE_DATA_SPHINCS_PARAMETER_SET = "data_sphincsParameterSet";
    public static final String ATTRIBUTE_DATA_SPHINCS_PARAMETER_SET_UUID = "8503651e-e779-489f-b819-ac7e262a208e";
    public static final String ATTRIBUTE_DATA_SPHINCS_PARAMETER_SET_LABEL = "Parameter Set";
    public static final String ATTRIBUTE_DATA_SPHINCS_PARAMETER_SET_DESCRIPTION = "Parameter set targeting a specific security level and signature size";

    public static final String ATTRIBUTE_DATA_SPHINCS_ROBUST = "data_sphincsRobust";
    public static final String ATTRIBUTE_DATA_SPHINCS_ROBUST_UUID = "6e64764c-7bc3-4af4-9bc4-9db8cac67286";
    public static final String ATTRIBUTE_DATA_SPHINCS_ROBUST_LABEL = "Use robust instantiation";
    public static final String ATTRIBUTE_DATA_SPHINCS_ROBUST_DESCRIPTION = "Robust instantiations. More conservative security argument but will be slower";

    public static List<BaseAttribute> getSphincsPLusKeySpecAttributes() {
        return List.of(
                buildDataHash(),
                buildDataParameterSet(),
                buildDataRobust()
        );
    }

    public static BaseAttribute buildDataHash() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_SPHINCS_HASH_UUID);
        attribute.setName(ATTRIBUTE_DATA_SPHINCS_HASH);
        attribute.setDescription(ATTRIBUTE_DATA_SPHINCS_HASH_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_SPHINCS_HASH_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(SphincsPlusHash.asStringAttributeContentList());

        return attribute;
    }

    public static BaseAttribute buildDataParameterSet() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_SPHINCS_PARAMETER_SET_UUID);
        attribute.setName(ATTRIBUTE_DATA_SPHINCS_PARAMETER_SET);
        attribute.setDescription(ATTRIBUTE_DATA_SPHINCS_PARAMETER_SET_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_SPHINCS_PARAMETER_SET_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(SphincsPlusParameterSet.asStringAttributeContentList());

        return attribute;
    }

    public static BaseAttribute buildDataRobust() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_SPHINCS_ROBUST_UUID);
        attribute.setName(ATTRIBUTE_DATA_SPHINCS_ROBUST);
        attribute.setDescription(ATTRIBUTE_DATA_SPHINCS_ROBUST_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.BOOLEAN);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_SPHINCS_ROBUST_LABEL);
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
