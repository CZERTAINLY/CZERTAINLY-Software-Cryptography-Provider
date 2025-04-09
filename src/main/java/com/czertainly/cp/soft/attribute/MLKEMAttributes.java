package com.czertainly.cp.soft.attribute;

import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.properties.DataAttributeProperties;
import com.czertainly.cp.soft.collection.MLKEMSecurityCategory;

import java.util.List;

public class MLKEMAttributes {

    private MLKEMAttributes() {
    }

    public static final String ATTRIBUTE_DATA_MLKEM_LEVEL = "data_mldsaLevel";
    public static final String ATTRIBUTE_DATA_MLKEM_LEVEL_UUID = "b574e0fb-9db5-4864-9652-40ccf9cff64d";
    public static final String ATTRIBUTE_DATA_MLKEM_LEVEL_LABEL = "NIST Security Category";
    public static final String ATTRIBUTE_DATA_MLKEM_LEVEL_DESCRIPTION = "Security strength according NIST definition";


    public static List<BaseAttribute> getMLKEMKeySpecAttributes() {
        return List.of(
                buildDataMLKEMSecurityCategory()
        );
    }

    public static BaseAttribute buildDataMLKEMSecurityCategory() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_MLKEM_LEVEL_UUID);
        attribute.setName(ATTRIBUTE_DATA_MLKEM_LEVEL);
        attribute.setDescription(ATTRIBUTE_DATA_MLKEM_LEVEL_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.INTEGER);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_MLKEM_LEVEL_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(MLKEMSecurityCategory.asIntegerAttributeContentList());

        return attribute;
    }
}
