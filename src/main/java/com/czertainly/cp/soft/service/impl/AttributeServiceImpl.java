package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.interfaces.connector.AttributesController;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.*;
import com.czertainly.api.model.common.attribute.v2.callback.AttributeCallback;
import com.czertainly.api.model.common.attribute.v2.callback.AttributeCallbackMapping;
import com.czertainly.api.model.common.attribute.v2.callback.AttributeValueTarget;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.TextAttributeContent;
import com.czertainly.api.model.common.attribute.v2.properties.DataAttributeProperties;
import com.czertainly.api.model.common.attribute.v2.properties.InfoAttributeProperties;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.service.AttributeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class AttributeServiceImpl implements AttributeService {
    private static final Logger logger = LoggerFactory.getLogger(AttributesController.class);

    public static final String ATTRIBUTE_INFO_INITIAL = "info_initial";
    public static final String ATTRIBUTE_INFO_INITIAL_UUID = "320c401a-9feb-402a-8f5b-0bfefcf155cc";
    public static final String ATTRIBUTE_INFO_INITIAL_LABEL = "Init Token";

    public static final String ATTRIBUTE_DATA_OPTIONS = "data_options";
    public static final String ATTRIBUTE_DATA_OPTIONS_UUID = "6285683f-f474-4b21-a0ff-56accf28c604";
    public static final String ATTRIBUTE_DATA_OPTIONS_LABEL = "Token options";

    public static final String ATTRIBUTE_GROUP_LOAD_TOKEN = "group_loadToken";
    public static final String ATTRIBUTE_GROUP_LOAD_TOKEN_UUID = "5dfc0040-a530-4faa-bc07-5fed6779b474";
    public static final String ATTRIBUTE_GROUP_LOAD_TOKEN_LABEL = "Token properties";

    @Override
    public List<BaseAttribute> getAttributes(String kind) {
        logger.debug("Getting the attributes for {}", kind);

        List<BaseAttribute> attrs = new ArrayList<>();

        // first attribute is to select from existing tokens, or create a new one
        attrs.add(buildInitialInfo());
        // create options to add new Token
        attrs.add(buildOptions());
        // load additional Attributes for the selected Token
        attrs.add(buildGroupBasedOnSelect());

        return attrs;
    }

    @Override
    public boolean validateAttributes(String kind, List<RequestAttributeDto> attributes) {
        if (attributes == null) {
            return false;
        }

        AttributeDefinitionUtils.validateAttributes(getAttributes(kind), attributes);
        return true;
    }

    private BaseAttribute buildInitialInfo() {
        // define Info Attribute
        InfoAttribute attribute = new InfoAttribute();
        attribute.setUuid(ATTRIBUTE_INFO_INITIAL_UUID);
        attribute.setName(ATTRIBUTE_INFO_INITIAL);
        attribute.setDescription(ATTRIBUTE_INFO_INITIAL_LABEL);
        attribute.setType(AttributeType.INFO);
        attribute.setContentType(AttributeContentType.TEXT);
        // create properties
        InfoAttributeProperties attributeProperties = new InfoAttributeProperties();
        attributeProperties.setLabel("Create new Token or select existing one");
        attributeProperties.setVisible(true);
        attribute.setProperties(attributeProperties);
        // create content
        String content = """
                You can select from existing Tokens when available, or create a new one.
                Based on the selection, additional information will be requested.
                """;
        attribute.setContent(List.of(new TextAttributeContent(content)));

        return attribute;
    }

    private BaseAttribute buildOptions() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_OPTIONS_UUID);
        attribute.setName(ATTRIBUTE_DATA_OPTIONS);
        attribute.setDescription(ATTRIBUTE_DATA_OPTIONS_LABEL);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel("Select the options to add Token");
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(List.of(
                new StringAttributeContent("new","Create new Token"),
                new StringAttributeContent("existing","Select existing Token")
        ));

        return attribute;
    }

    private BaseAttribute buildGroupBasedOnSelect() {
        // define Group Attribute
        GroupAttribute attribute = new GroupAttribute();
        attribute.setUuid(ATTRIBUTE_GROUP_LOAD_TOKEN_UUID);
        attribute.setName(ATTRIBUTE_GROUP_LOAD_TOKEN);
        attribute.setType(AttributeType.GROUP);
        attribute.setDescription(ATTRIBUTE_GROUP_LOAD_TOKEN_LABEL);
        // prepare mappings for callback
        Set<AttributeCallbackMapping> mappings = new HashSet<>();
        mappings.add(new AttributeCallbackMapping(ATTRIBUTE_DATA_OPTIONS + ".reference", "option", AttributeValueTarget.PATH_VARIABLE));
        // create attribute callback
        AttributeCallback attributeCallback = new AttributeCallback();
        attributeCallback.setCallbackContext("/v1/cryptographyProvider/{option}/attributes");
        attributeCallback.setCallbackMethod("GET");
        attributeCallback.setMappings(mappings);
        // set attribute callback
        attribute.setAttributeCallback(attributeCallback);

        return attribute;
    }

}
