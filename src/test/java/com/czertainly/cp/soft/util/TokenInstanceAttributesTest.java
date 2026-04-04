package com.czertainly.cp.soft.util;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.attribute.TokenInstanceAttributes;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@SpringBootTest
class TokenInstanceAttributesTest {

    @Test
    void testTokenNameAttributeMatching_ok() {

        List<BaseAttribute> definition = new ArrayList<>();
        definition.add(TokenInstanceAttributes.buildDataNewTokenName());

        List<RequestAttribute> request = new ArrayList<>();
        RequestAttributeV2 requestAttributeDto = new RequestAttributeV2();
        requestAttributeDto.setName(definition.get(0).getName());
        requestAttributeDto.setUuid(UUID.fromString(definition.get(0).getUuid()));
        List<BaseAttributeContentV2<?>> contents = new ArrayList<>();
        StringAttributeContentV2 content = new StringAttributeContentV2();
        content.setReference("reference");
        content.setData("Aa_aa");
        contents.add(content);
        requestAttributeDto.setContent(contents);
        request.add(requestAttributeDto);

        Assertions.assertDoesNotThrow(() -> AttributeDefinitionUtils.validateAttributes(definition, request));
    }

}
