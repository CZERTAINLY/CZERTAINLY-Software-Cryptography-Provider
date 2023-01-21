package com.czertainly.cp.soft.attribute;

import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import com.czertainly.api.model.common.attribute.v2.properties.DataAttributeProperties;
import com.czertainly.api.model.common.attribute.v2.properties.MetadataAttributeProperties;
import com.czertainly.cp.soft.collection.FalconDegree;

import java.util.List;

public class FalconKeyAttributes {

    // Falcon Attributes
    public static final String ATTRIBUTE_DATA_FALCON_DEGREE = "data_falconDegree";
    public static final String ATTRIBUTE_DATA_FALCON_DEGREE_UUID = "d4d86b9a-b5df-4a1b-8d9d-1671cfb4b496";
    public static final String ATTRIBUTE_DATA_FALCON_DEGREE_LABEL = "Falcon Key Degree";
    public static final String ATTRIBUTE_DATA_FALCON_DEGREE_DESCRIPTION = "Degree (n) of the Falcon Key";

    public static final String ATTRIBUTE_META_FALCON_DEGREE = "meta_falconDegree";
    public static final String ATTRIBUTE_META_FALCON_DEGREE_UUID = "bd9b2826-f7fc-4bc3-b817-66bc231f1ee2";
    public static final String ATTRIBUTE_META_FALCON_DEGREE_LABEL = "Falcon Key Degree";
    public static final String ATTRIBUTE_META_FALCON_DEGREE_DESCRIPTION = "Degree (n) of the Falcon Key";

    public static List<BaseAttribute> getFalconKeySpecAttributes() {
        return List.of(
                buildDataFalconDegree()
        );
    }

    public static BaseAttribute buildDataFalconDegree() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_FALCON_DEGREE_UUID);
        attribute.setName(ATTRIBUTE_DATA_FALCON_DEGREE);
        attribute.setDescription(ATTRIBUTE_DATA_FALCON_DEGREE_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.INTEGER);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_FALCON_DEGREE_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(FalconDegree.asIntegerAttributeContentList());

        return attribute;
    }

    public static MetadataAttribute buildFalconDegreeMetadata(int degree) {
        // define Metadata Attribute
        MetadataAttribute metadataAttribute = new MetadataAttribute();
        metadataAttribute.setUuid(ATTRIBUTE_META_FALCON_DEGREE_UUID);
        metadataAttribute.setName(ATTRIBUTE_META_FALCON_DEGREE);
        metadataAttribute.setType(AttributeType.META);
        metadataAttribute.setContentType(AttributeContentType.STRING);
        metadataAttribute.setDescription(ATTRIBUTE_META_FALCON_DEGREE_DESCRIPTION);
        // create properties
        MetadataAttributeProperties metadataAttributeProperties = new MetadataAttributeProperties();
        metadataAttributeProperties.setLabel(ATTRIBUTE_META_FALCON_DEGREE_LABEL);
        metadataAttributeProperties.setVisible(true);
        metadataAttributeProperties.setGlobal(false);
        metadataAttribute.setProperties(metadataAttributeProperties);
        // create IntegerAttributeContent
        IntegerAttributeContent integerAttributeContent = new IntegerAttributeContent();
        integerAttributeContent.setReference("degree");
        integerAttributeContent.setData(degree);
        metadataAttribute.setContent(List.of(integerAttributeContent));

        return metadataAttribute;
    }

}
