package com.czertainly.cp.soft.api;

import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.cp.soft.attribute.*;
import com.czertainly.cp.soft.exception.NotSupportedException;
import com.czertainly.cp.soft.service.TokenInstanceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/v1/cryptographyProvider/callbacks")
public class CallbackController {

    private TokenInstanceService tokenInstanceService;

    @Autowired
    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @RequestMapping(
            path = "/keyspec/{algorithm}/attributes",
            method = RequestMethod.GET,
            produces = "application/json"
    )
    public List<BaseAttribute> getKeySpecAttributes(
            @PathVariable KeyAlgorithm algorithm) {

        switch (algorithm) {
            case RSA -> {
                return RsaKeyAttributes.getRsaKeySpecAttributes();
            }
            case ECDSA -> {
                return EcdsaKeyAttributes.getEcdsaKeySpecAttributes();
            }
            case FALCON -> {
                return FalconKeyAttributes.getFalconKeySpecAttributes();
            }
            case DILITHIUM -> {
                return DilithiumKeyAttributes.getDilithiumKeySpecAttributes();
            }
            case SPHINCSPLUS -> {
                return SphincsPlusKeyAttributes.getSphincsPLusKeySpecAttributes();
            }
            default -> throw new NotSupportedException("Algorithm not supported");
        }

    }

    @RequestMapping(
            path = "/token/{option}/attributes",
            method = RequestMethod.GET,
            produces = "application/json"
    )
    public List<BaseAttribute> getCreateTokenAttributes(
            @PathVariable String option) {

        switch (option) {
            case "new" -> {
                return TokenInstanceAttributes.getNewTokenAttributesWithoutInfo();
            }
            case "existing" -> {
                return TokenInstanceAttributes.getExistingTokenAttributes(tokenInstancesToStringContentList(tokenInstanceService.listTokenInstances()));
            }
            default -> throw new NotSupportedException("Option for token creation not supported");
        }

    }

    private List<BaseAttributeContent> tokenInstancesToStringContentList(List<TokenInstanceDto> tokenInstanceDtos) {
        return tokenInstanceDtos.stream()
                .map(tokenInstanceDto -> {
                    return new StringAttributeContent(tokenInstanceDto.getName(), tokenInstanceDto.getUuid());
                })
                .collect(Collectors.toList());
    }

}
