package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.content.SecretAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.data.SecretAttributeContentData;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceRequestDto;
import com.czertainly.cp.soft.attribute.TokenInstanceAttributes;
import com.czertainly.cp.soft.service.TokenInstanceService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@SpringBootTest
public class TokenInstanceServiceImplTest {

    private TokenInstanceService tokenInstanceService;

    @Autowired
    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Test
    public void testTokenDeleteOnRemoveFalse() throws AlreadyExistException, NotFoundException {
        // create dummy token instance
        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setKind("SOFT");
        request.setName("DummyToken");

        List<RequestAttributeDto> attributes = new ArrayList<>();

        RequestAttributeDto data_newTokenName = new RequestAttributeDto();
        data_newTokenName.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME);
        data_newTokenName.setContent(List.of(
                new StringAttributeContent( "DummyToken")
        ));
        attributes.add(data_newTokenName);

        RequestAttributeDto data_createTokenAction = new RequestAttributeDto();
        data_createTokenAction.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION);
        data_createTokenAction.setContent(List.of(
                new StringAttributeContent( "new", "new")
        ));
        attributes.add(data_createTokenAction);

        RequestAttributeDto data_options = new RequestAttributeDto();
        data_options.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_OPTIONS);
        data_options.setContent(List.of(
                new StringAttributeContent( "new", "Create new Token")
        ));
        attributes.add(data_options);

        RequestAttributeDto data_tokenCode = new RequestAttributeDto();
        data_tokenCode.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE);
        data_tokenCode.setContent(List.of(
                new SecretAttributeContent("DummyToken", new SecretAttributeContentData("00000000"))
        ));
        attributes.add(data_tokenCode);

        request.setAttributes(attributes);

        TokenInstanceDto token = tokenInstanceService.createTokenInstance(request);

        // delete token instance
        tokenInstanceService.removeTokenInstance(UUID.fromString(token.getUuid()));

        // check if token instance is still in database
        // it will throw NotFoundException if token instance is not in database
        Assertions.assertDoesNotThrow(tokenInstanceService.getTokenInstanceStatus(UUID.fromString(token.getUuid())););
    }

}
