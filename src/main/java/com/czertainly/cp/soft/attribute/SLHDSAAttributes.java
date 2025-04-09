package com.czertainly.cp.soft.attribute;

import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.properties.DataAttributeProperties;
import com.czertainly.cp.soft.collection.SlhDSAHash;
import com.czertainly.cp.soft.collection.SLHDSASecurityCategory;
import com.czertainly.cp.soft.collection.SLHDSATradeoff;

import java.util.List;

public class SLHDSAAttributes {

    private SLHDSAAttributes() {
    }

    public static final String ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY = "data_slhdsaSecurityCategory";
    public static final String ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_UUID = "8503651e-e779-489f-b819-ac7e262a208e";
    public static final String ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_LABEL = "NIST Security Category";
    public static final String ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_DESCRIPTION = "Strength of algorithm according to NIST";

    public static final String ATTRIBUTE_DATA_SLHDSA_HASH = "data_slhdsaHash";
    public static final String ATTRIBUTE_DATA_SLHDSA_HASH_UUID = "563eeac3-68a5-4d11-8015-0a6bceb1b9c2";
    public static final String ATTRIBUTE_DATA_SLHDSA_HASH_LABEL = "Hash Function";
    public static final String ATTRIBUTE_DATA_SLHDSA_HASH_DESCRIPTION = "Hash function used to instantiate the signature scheme";

    public static final String ATTRIBUTE_DATA_SLHDSA_TRADEOFF = "data_slhdsaPurpose";
    public static final String ATTRIBUTE_DATA_SLHDSA_TRADEOFF_UUID = "6e64764c-7bc3-4af4-9bc4-9db8cac67286";
    public static final String ATTRIBUTE_DATA_SLHDSA_TRADEOFF_LABEL = "Signature generation trade-off";
    public static final String ATTRIBUTE_DATA_SLHDSA_TRADEOFF_DESCRIPTION = "Create relatively small signatures or have relatively fast signature generation";

    public static final String ATTRIBUTE_DATA_USE_PREHASH = "data_slhdsaPrehash";


    public static List<BaseAttribute> getSlhDsaKeySpecAttributes() {
        return List.of(
                buildDataSecurityCategory(),
                buildDataHash(),
                buildDataTradeoff()
        );
    }

    public static BaseAttribute buildDataHash() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_SLHDSA_HASH_UUID);
        attribute.setName(ATTRIBUTE_DATA_SLHDSA_HASH);
        attribute.setDescription(ATTRIBUTE_DATA_SLHDSA_HASH_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_SLHDSA_HASH_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(SlhDSAHash.asStringAttributeContentList());

        return attribute;
    }

    public static BaseAttribute buildDataSecurityCategory() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_UUID);
        attribute.setName(ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY);
        attribute.setDescription(ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(SLHDSASecurityCategory.asStringAttributeContentList());

        return attribute;
    }

    public static BaseAttribute buildDataTradeoff() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_SLHDSA_TRADEOFF_UUID);
        attribute.setName(ATTRIBUTE_DATA_SLHDSA_TRADEOFF);
        attribute.setDescription(ATTRIBUTE_DATA_SLHDSA_TRADEOFF_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_SLHDSA_TRADEOFF_LABEL);
        attributeProperties.setRequired(false);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(SLHDSATradeoff.asStringAttributeContentList());

        return attribute;
    }

}
