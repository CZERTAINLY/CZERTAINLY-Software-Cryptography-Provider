package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.czertainly.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
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
class TokenInstanceServiceImplTest {

    private TokenInstanceService tokenInstanceService;

    @Autowired
    void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Test
    void testTokenDeleteOnRemoveFalse() throws AlreadyExistException, NotFoundException {
        // create dummy token instance
        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setKind("SOFT");
        request.setName("DummyToken");

        List<RequestAttribute> attributes = new ArrayList<>();

        RequestAttributeV2 data_newTokenName = new RequestAttributeV2();
        data_newTokenName.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME);
        data_newTokenName.setContent(List.of(
                new StringAttributeContentV2( "DummyToken")
        ));
        attributes.add(data_newTokenName);

        RequestAttributeV2 data_createTokenAction = new RequestAttributeV2();
        data_createTokenAction.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION);
        data_createTokenAction.setContent(List.of(
                new StringAttributeContentV2( "new", "new")
        ));
        attributes.add(data_createTokenAction);

        RequestAttributeV2 data_options = new RequestAttributeV2();
        data_options.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_OPTIONS);
        data_options.setContent(List.of(
                new StringAttributeContentV2( "new", "Create new Token")
        ));
        attributes.add(data_options);

        RequestAttributeV2 data_tokenCode = new RequestAttributeV2();
        data_tokenCode.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE);
        data_tokenCode.setContent(List.of(
                new SecretAttributeContentV2("DummyToken", new SecretAttributeContentData("00000000"))
        ));
        attributes.add(data_tokenCode);

        request.setAttributes(attributes);

        TokenInstanceDto token = tokenInstanceService.createTokenInstance(request);

        // delete token instance
        tokenInstanceService.removeTokenInstance(UUID.fromString(token.getUuid()));

        // check if token instance is still in database
        // it will throw NotFoundException if token instance is not in database
        Assertions.assertDoesNotThrow(() -> tokenInstanceService.getTokenInstanceStatus(UUID.fromString(token.getUuid())));
    }

}
