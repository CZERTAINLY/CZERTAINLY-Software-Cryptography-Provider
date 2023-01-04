package com.czertainly.cp.soft.util;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.attribute.TokenInstanceAttributes;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;

@SpringBootTest
public class TokenInstanceAttributesTest {

    @Test
    public void testTokenNameAttributeMatching_ok() {

        List<BaseAttribute> definition = new ArrayList<>();
        definition.add(TokenInstanceAttributes.buildDataNewTokenName());

        List<RequestAttributeDto> request = new ArrayList<>();
        RequestAttributeDto requestAttributeDto = new RequestAttributeDto();
        requestAttributeDto.setName(definition.get(0).getName());
        requestAttributeDto.setUuid(definition.get(0).getUuid());
        List<BaseAttributeContent> contents = new ArrayList<>();
        StringAttributeContent content = new StringAttributeContent();
        content.setReference("reference");
        content.setData("Aa_aa");
        contents.add(content);
        requestAttributeDto.setContent(contents);
        request.add(requestAttributeDto);

        Assertions.assertDoesNotThrow(() -> AttributeDefinitionUtils.validateAttributes(definition, request));
    }

}
