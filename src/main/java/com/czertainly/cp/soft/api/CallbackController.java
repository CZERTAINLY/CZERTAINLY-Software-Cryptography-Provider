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
import org.springframework.web.bind.annotation.*;

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

    @GetMapping(
            path = "/keyspec/{algorithm}/attributes",
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
            case MLDSA -> {
                return MLDSAKeyAttributes.getMldsaKeySpecAttributes();
            }
            case SLHDSA -> {
                return SLHDSAAttributes.getSlhDsaKeySpecAttributes();
            }
            case MLKEM -> {
                return MLKEMAttributes.getMLKEMKeySpecAttributes();
            }
            default -> throw new NotSupportedException("Algorithm not supported");
        }

    }

    @GetMapping(
            path = "/token/{option}/attributes",
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
                .map(tokenInstanceDto -> new StringAttributeContent(tokenInstanceDto.getName(), tokenInstanceDto.getUuid()))
                .collect(Collectors.toList());
    }

}
