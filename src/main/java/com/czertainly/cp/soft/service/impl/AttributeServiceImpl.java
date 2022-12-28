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
import com.czertainly.cp.soft.service.TokenInstanceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class AttributeServiceImpl implements AttributeService {
    private static final Logger logger = LoggerFactory.getLogger(AttributesController.class);

    @Autowired
    private TokenInstanceService tokenInstanceService;

//    @Autowired
//    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
//        this.tokenInstanceService = tokenInstanceService;
//    }

    public static final String ATTRIBUTE_INFO_INITIAL = "info_initial";
    public static final String ATTRIBUTE_INFO_INITIAL_UUID = "320c401a-9feb-402a-8f5b-0bfefcf155cc";
    public static final String ATTRIBUTE_INFO_INITIAL_LABEL = "Init Token";

    public static final String ATTRIBUTE_DATA_OPTIONS = "data_options";
    public static final String ATTRIBUTE_DATA_OPTIONS_UUID = "6285683f-f474-4b21-a0ff-56accf28c604";
    public static final String ATTRIBUTE_DATA_OPTIONS_LABEL = "Token options";

    public static final String ATTRIBUTE_GROUP_LOAD_TOKEN = "group_loadToken";
    public static final String ATTRIBUTE_GROUP_LOAD_TOKEN_UUID = "5dfc0040-a530-4faa-bc07-5fed6779b474";
    public static final String ATTRIBUTE_GROUP_LOAD_TOKEN_LABEL = "Token properties";

    public static final String ATTRIBUTE_INFO_NEW_TOKEN = "info_newToken";
    public static final String ATTRIBUTE_INFO_NEW_TOKEN_UUID = "15943f63-8b06-45f6-bad6-58e0998b654b";
    public static final String ATTRIBUTE_INFO_NEW_TOKEN_LABEL = "Create new Token";
    public static final String ATTRIBUTE_INFO_NEW_TOKEN_DESCRIPTION = "Information about creating new Token";

    public static final String ATTRIBUTE_DATA_NEW_TOKEN_NAME = "data_newTokenName";
    public static final String ATTRIBUTE_DATA_NEW_TOKEN_NAME_UUID = "21a79858-a246-4b2a-93e1-1677c8beb6a4";
    public static final String ATTRIBUTE_DATA_NEW_TOKEN_NAME_LABEL = "New Token name";
    public static final String ATTRIBUTE_DATA_NEW_TOKEN_NAME_DESCRIPTION = "Provide name for the new Token that will be created";

    public static final String ATTRIBUTE_DATA_NEW_TOKEN_CODE = "data_newTokenCode";
    public static final String ATTRIBUTE_DATA_NEW_TOKEN_CODE_UUID = "181aae19-d2a3-40ca-b5c7-570c8dfbb3cb";
    public static final String ATTRIBUTE_DATA_NEW_TOKEN_CODE_LABEL = "New Token activation code";
    public static final String ATTRIBUTE_DATA_NEW_TOKEN_CODE_DESCRIPTION = "Activation code that will be used to activate this new Token";

    public static final String ATTRIBUTE_DATA_CREATE_TOKEN_ACTION = "data_createTokenAction";
    public static final String ATTRIBUTE_DATA_CREATE_TOKEN_ACTION_UUID = "cc781ba3-d90b-4fe9-915a-e8d44e1cff86";

    /////////////////////////////////////////////////
    // Token instance activation Attributes
    /////////////////////////////////////////////////

    public static final String ATTRIBUTE_DATA_ACTIVATION_CODE = "data_tokenActivationCode";
    public static final String ATTRIBUTE_DATA_ACTIVATION_CODE_UUID = "0d4044f0-2af0-4f10-ac09-319072eb3393";
    public static final String ATTRIBUTE_DATA_ACTIVATION_CODE_LABEL = "Token activation code";
    public static final String ATTRIBUTE_DATA_ACTIVATION_CODE_DESCRIPTION = "Activation code that will be used to activate this Token";


    @Override
    public List<BaseAttribute> getAttributes(String kind) {
        logger.debug("Getting the attributes for {}", kind);

        // when we do not have Tokens, return attributes to create new
        if (tokenInstanceService.listTokenInstances() == null) {
            return getAttributesForNewToken();
        } else {
            List<BaseAttribute> attrs = new ArrayList<>();

            // first attribute is to select from existing tokens, or create a new one
            attrs.add(buildInitialInfo());
            // create options to add new Token
            attrs.add(buildOptions());
            // load additional Attributes for the selected Token
            attrs.add(buildGroupBasedOnSelect());

            return attrs;
        }
    }

    @Override
    public boolean validateAttributes(String kind, List<RequestAttributeDto> attributes) {
        if (attributes == null) {
            return false;
        }

        AttributeDefinitionUtils.validateAttributes(getAttributes(kind), attributes);
        return true;
    }

    @Override
    public List<BaseAttribute> getTokenInstanceActivationAttributes(String kind) {
        logger.debug("Getting Token instance activation attributes for {}", kind);

        List<BaseAttribute> attrs = new ArrayList<>();

        attrs.add(buildDataTokenActivationCode());

        return attrs;
    }

    @Override
    public boolean validateTokenInstanceActivationAttributes(String kind, List<RequestAttributeDto> attributes) {
        if (attributes == null) {
            return false;
        }

        AttributeDefinitionUtils.validateAttributes(getTokenInstanceActivationAttributes(kind), attributes);
        return true;
    }

    private BaseAttribute buildDataTokenActivationCode() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_ACTIVATION_CODE_UUID);
        attribute.setName(ATTRIBUTE_DATA_ACTIVATION_CODE);
        attribute.setDescription(ATTRIBUTE_DATA_ACTIVATION_CODE_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.SECRET);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_ACTIVATION_CODE_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(false);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);

        return attribute;
    }


    private List<BaseAttribute> getAttributesForNewToken() {
        List<BaseAttribute> attrs = new ArrayList<>();

        attrs.add(buildDataCreateTokenAction("new"));
        attrs.add(buildInfoNewToken());
        attrs.add(buildDataNewTokenName());
        attrs.add(buildDataNewTokenCode());

        return attrs;
    }

    private BaseAttribute buildDataCreateTokenAction(String action) {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_CREATE_TOKEN_ACTION_UUID);
        attribute.setName(ATTRIBUTE_DATA_CREATE_TOKEN_ACTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(false);
        attributeProperties.setList(false);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(true);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(List.of(
                new StringAttributeContent(action,action)
        ));

        return attribute;
    }

    private BaseAttribute buildInfoNewToken() {
        // define Info Attribute
        InfoAttribute attribute = new InfoAttribute();
        attribute.setUuid(ATTRIBUTE_INFO_NEW_TOKEN_UUID);
        attribute.setName(ATTRIBUTE_INFO_NEW_TOKEN);
        attribute.setDescription(ATTRIBUTE_INFO_NEW_TOKEN_DESCRIPTION);
        attribute.setType(AttributeType.INFO);
        attribute.setContentType(AttributeContentType.TEXT);
        // create properties
        InfoAttributeProperties attributeProperties = new InfoAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_INFO_NEW_TOKEN_LABEL);
        attributeProperties.setVisible(true);
        attribute.setProperties(attributeProperties);
        // create content
        String content = """
                It seems that there are no existing Tokens available. You can create a new one by providing the name and activation code below.
                """;
        attribute.setContent(List.of(new TextAttributeContent(content)));

        return attribute;
    }

    private BaseAttribute buildDataNewTokenName() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_NEW_TOKEN_NAME_UUID);
        attribute.setName(ATTRIBUTE_DATA_NEW_TOKEN_NAME);
        attribute.setDescription(ATTRIBUTE_DATA_NEW_TOKEN_NAME_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_NEW_TOKEN_NAME_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(false);
        attributeProperties.setMultiSelect(false);
        attribute.setProperties(attributeProperties);

        return attribute;
    }

    private BaseAttribute buildDataNewTokenCode() {
        // define Data Attribute
        DataAttribute attribute = new DataAttribute();
        attribute.setUuid(ATTRIBUTE_DATA_NEW_TOKEN_CODE_UUID);
        attribute.setName(ATTRIBUTE_DATA_NEW_TOKEN_CODE);
        attribute.setDescription(ATTRIBUTE_DATA_NEW_TOKEN_CODE_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.SECRET);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_NEW_TOKEN_CODE_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(false);
        attributeProperties.setMultiSelect(false);
        attribute.setProperties(attributeProperties);

        return attribute;
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
