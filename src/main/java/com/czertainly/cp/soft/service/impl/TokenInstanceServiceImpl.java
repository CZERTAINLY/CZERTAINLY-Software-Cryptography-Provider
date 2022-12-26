package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.attribute.v2.content.SecretAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceRequestDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.dao.entity.TokenInstance;
import com.czertainly.cp.soft.dao.repository.TokenInstanceRepository;
import com.czertainly.cp.soft.service.TokenInstanceService;
import com.czertainly.cp.soft.util.KeyStoreUtil;
import com.czertainly.cp.soft.util.SecretEncodingVersion;
import com.czertainly.cp.soft.util.SecretsUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class TokenInstanceServiceImpl implements TokenInstanceService {

    private TokenInstanceRepository tokenInstanceRepository;

    @Autowired
    public void setTokenInstanceRepository(TokenInstanceRepository tokenInstanceRepository) {
        this.tokenInstanceRepository = tokenInstanceRepository;
    }


    @Override
    public List<TokenInstanceDto> listTokenInstances() {
        List<TokenInstance> tokens;
        tokens = tokenInstanceRepository.findAll();
        if (!tokens.isEmpty()) {
            return tokens
                    .stream().map(TokenInstance::mapToDto)
                    .collect(Collectors.toList());
        }
        return null;
    }

    @Override
    public TokenInstanceDto getTokenInstance(UUID uuid) throws NotFoundException {
        return tokenInstanceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenInstance.class, uuid))
                .mapToDto();
    }

    @Override
    public TokenInstanceDto createTokenInstance(TokenInstanceRequestDto request) throws AlreadyExistException {
        final String action = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                AttributeServiceImpl.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION, request.getAttributes(), StringAttributeContent.class).getData();

        if (action.equals("new")) {
            final String tokenName = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                    AttributeServiceImpl.ATTRIBUTE_DATA_NEW_TOKEN_NAME, request.getAttributes(), StringAttributeContent.class).getData();

            if (tokenInstanceRepository.findByName(tokenName).isPresent()) {
                throw new AlreadyExistException(TokenInstance.class, request.getName());
            }

            final String tokenCode = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                    AttributeServiceImpl.ATTRIBUTE_DATA_NEW_TOKEN_CODE, request.getAttributes(), SecretAttributeContent.class).getData().getSecret();

            byte[] tokenData = KeyStoreUtil.createNewKeystore("PKCS12", tokenCode);

            TokenInstance instance = new TokenInstance();
            instance.setUuid(UUID.randomUUID().toString());
            instance.setName(tokenName);
            instance.setCode(
                    SecretsUtil.encryptAndEncodeSecretString(tokenCode, SecretEncodingVersion.V1)
            );
            instance.setData(tokenData);

            //AttributeDefinitionUtils.serializeRequestAttributes(request.getAttributes());
            //instance.setRequestAttributes(request.getAttributes());

            tokenInstanceRepository.save(instance);

            return instance.mapToDto();
        } else if (action.equals("existing")) {
            final String tokenName = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                    AttributeServiceImpl.ATTRIBUTE_DATA_NEW_TOKEN_NAME, request.getAttributes(), StringAttributeContent.class).getData();

            // TODO: change exception in method signature

            return tokenInstanceRepository.findByName(tokenName)
                    .orElseThrow(() -> new AlreadyExistException(TokenInstance.class, tokenName))
                    .mapToDto();
        } else {
            throw new IllegalArgumentException("Unknown operation to create Token: " + action);
        }
    }


    @Override
    public boolean containsTokens() {
        return listTokenInstances() != null;
    }



}
