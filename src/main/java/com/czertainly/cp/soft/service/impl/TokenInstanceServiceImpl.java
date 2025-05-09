package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.SecretAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.properties.MetadataAttributeProperties;
import com.czertainly.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceRequestDto;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceStatusDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.attribute.TokenInstanceActivationAttributes;
import com.czertainly.cp.soft.attribute.TokenInstanceAttributes;
import com.czertainly.cp.soft.dao.entity.TokenInstance;
import com.czertainly.cp.soft.dao.repository.TokenInstanceRepository;
import com.czertainly.cp.soft.exception.NotSupportedException;
import com.czertainly.cp.soft.exception.TokenInstanceException;
import com.czertainly.cp.soft.service.TokenInstanceService;
import com.czertainly.cp.soft.util.KeyStoreUtil;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
public class TokenInstanceServiceImpl implements TokenInstanceService {

    private static final Logger logger = LoggerFactory.getLogger(TokenInstanceServiceImpl.class);

    private TokenInstanceRepository tokenInstanceRepository;

    @Autowired
    public void setTokenInstanceRepository(TokenInstanceRepository tokenInstanceRepository) {
        this.tokenInstanceRepository = tokenInstanceRepository;
    }

    @Value("${token.deleteOnRemove}")
    private boolean deleteOnRemove;

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
    public TokenInstance getTokenInstanceEntity(UUID uuid) throws NotFoundException {
        return tokenInstanceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenInstance.class, uuid));
    }

    @Override
    public TokenInstanceDto createTokenInstance(TokenInstanceRequestDto request) throws AlreadyExistException {
        final String action = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION, request.getAttributes(), StringAttributeContent.class).getData();

        if (action.equals("new")) {
            final String tokenName = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                    TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME, request.getAttributes(), StringAttributeContent.class).getData();

            if (tokenInstanceRepository.findByName(tokenName).isPresent()) {
                throw new AlreadyExistException(TokenInstance.class, request.getName());
            }

            final String tokenCode = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                    TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE, request.getAttributes(), SecretAttributeContent.class).getData().getSecret();

            byte[] tokenData = KeyStoreUtil.createNewKeystore("PKCS12", tokenCode);

            TokenInstance instance = new TokenInstance();
            instance.setUuid(UUID.randomUUID().toString());
            instance.setName(tokenName);
            instance.setCode(tokenCode);
            instance.setData(tokenData);

            List<MetadataAttribute> attributes = new ArrayList<>();
            attributes.add(buildNameMetadata(tokenName));

            instance.setMetadata(attributes);

            tokenInstanceRepository.save(instance);

            return instance.mapToDto();
        } else if (action.equals("existing")) {
            final String tokenUuid = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                    TokenInstanceAttributes.ATTRIBUTE_DATA_SELECT_EXISTING_TOKEN, request.getAttributes(), StringAttributeContent.class).getData();

            final String tokenName = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                    TokenInstanceAttributes.ATTRIBUTE_DATA_SELECT_EXISTING_TOKEN, request.getAttributes(), StringAttributeContent.class).getReference();

            TokenInstance tokenInstance = tokenInstanceRepository.findByUuid(UUID.fromString(tokenUuid))
                    .orElseThrow(() -> new TokenInstanceException("Token " + tokenName + "(" + tokenUuid + ") not found"));

            // try to activate token using provided code
            final String tokenCode = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                    TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE, request.getAttributes(), SecretAttributeContent.class).getData().getSecret();
            try {
                KeyStoreUtil.loadKeystore(tokenInstance.getData(), tokenCode);
            } catch (IllegalStateException | UnrecoverableKeyException e) {
                logger.debug("Token activation failed", e);
                throw new TokenInstanceException("Cannot activate token " + tokenInstance.getName() + ": " + e.getMessage());
            }

            return tokenInstance.mapToDto();
        } else {
            throw new TokenInstanceException("Unknown operation to create Token: " + action);
        }
    }

    @Override
    public void removeTokenInstance(UUID uuid) throws NotFoundException {
        TokenInstance token =  tokenInstanceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenInstance.class, uuid));

        if (deleteOnRemove) {
            logger.debug("Removing token instance from database: {}", token);
            tokenInstanceRepository.delete(token);
        } else {
            logger.debug("Delete is disabled, keeping the token instance {} in database", token);
        }
    }

    @Override
    public TokenInstanceStatusDto getTokenInstanceStatus(UUID uuid) throws NotFoundException {
        TokenInstance token =  tokenInstanceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenInstance.class, uuid));

        TokenInstanceStatusDto status = new TokenInstanceStatusDto();

        if (token.getCode() != null) {
            status.setStatus(TokenInstanceStatus.ACTIVATED);
        } else {
            status.setStatus(TokenInstanceStatus.DEACTIVATED);
        }

        return status;
    }

    @Override
    public void activateTokenInstance(UUID uuid, List<RequestAttributeDto> attributes) throws NotFoundException, TokenInstanceException {
        TokenInstance token =  tokenInstanceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenInstance.class, uuid));

        // if the activation code is present, we assume it is correct, not checking the activation of the Token
        if (token.getCode() != null) {
            throw new TokenInstanceException("Token instance already activated");
        } else {
            final String tokenCode = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                    TokenInstanceActivationAttributes.ATTRIBUTE_DATA_ACTIVATION_CODE, attributes, SecretAttributeContent.class).getData().getSecret();
            try {
                KeyStoreUtil.loadKeystore(token.getData(), tokenCode);
            } catch (IllegalStateException e) {
                logger.debug("Token activation failed", e);
                throw new TokenInstanceException("Cannot activate token " + token.getName() + ": " + e.getMessage());
            } catch (UnrecoverableKeyException e) {
                throw new NotSupportedException("Cannot recover keys from token.");
            }

            token.setCode(tokenCode);

            tokenInstanceRepository.save(token);
        }
    }

    @Override
    public void deactivateTokenInstance(UUID uuid) throws NotFoundException, TokenInstanceException {
        TokenInstance token =  tokenInstanceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenInstance.class, uuid));

        if (token.getCode() == null) {
            throw new TokenInstanceException("Token instance already deactivated");
        } else {
            token.setCode(null);
            tokenInstanceRepository.save(token);
        }
    }

    @Override
    public boolean containsTokens() {
        return listTokenInstances() != null;
    }

    @Override
    public void saveTokenInstance(TokenInstance tokenInstance) {
        tokenInstanceRepository.save(tokenInstance);
    }

    private MetadataAttribute buildNameMetadata(String name) {
        // define Metadata Attribute
        MetadataAttribute metadataAttribute = new MetadataAttribute();
        metadataAttribute.setUuid("81d8c383-e499-4914-b6de-d92139bfe742");
        metadataAttribute.setName("meta_tokenName");
        metadataAttribute.setType(AttributeType.META);
        metadataAttribute.setContentType(AttributeContentType.STRING);
        metadataAttribute.setDescription("Reference name of the Token instance");
        // create properties
        MetadataAttributeProperties metadataAttributeProperties = new MetadataAttributeProperties();
        metadataAttributeProperties.setLabel("Token instance name");
        metadataAttributeProperties.setVisible(true);
        metadataAttributeProperties.setGlobal(false);
        metadataAttribute.setProperties(metadataAttributeProperties);
        // create StringAttributeContent
        StringAttributeContent stringAttributeContent = new StringAttributeContent();
        stringAttributeContent.setReference("tokenName");
        stringAttributeContent.setData(name);
        metadataAttribute.setContent(List.of(stringAttributeContent));

        return metadataAttribute;
    }

}
