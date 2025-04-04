package com.czertainly.cp.soft.attribute;

import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.properties.DataAttributeProperties;
import com.czertainly.cp.soft.collection.MLDSASecurityCategory;

import java.util.List;

public class MLDSAKeyAttributes {

    public static final String ATTRIBUTE_DATA_MLDSA_LEVEL = "data_mldsaLevel";
    public static final String ATTRIBUTE_DATA_MLDSA_LEVEL_UUID = "88a0fa46-dcdd-4d29-a51c-e563e21c9872";
    public static final String ATTRIBUTE_DATA_MLDSA_LEVEL_LABEL = "NIST Security Category";
    public static final String ATTRIBUTE_DATA_MLDSA_LEVEL_DESCRIPTION = "Security strength according NIST definition";

    public static final String ATTRIBUTE_DATA_USE_PREHASH = "data_mldsaPrehash";

    public static List<BaseAttribute> getMldsaKeySpecAttributes() {
        return List.of(
                buildDataMLDSASecurityCategory()
        );
    }

    public static BaseAttribute buildDataMLDSASecurityCategory() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_MLDSA_LEVEL_UUID);
        attribute.setName(ATTRIBUTE_DATA_MLDSA_LEVEL);
        attribute.setDescription(ATTRIBUTE_DATA_MLDSA_LEVEL_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.INTEGER);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_MLDSA_LEVEL_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(MLDSASecurityCategory.asIntegerAttributeContentList());

        return attribute;
    }

}
