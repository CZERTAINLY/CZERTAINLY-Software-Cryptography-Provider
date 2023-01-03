package com.czertainly.cp.soft.api;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.interfaces.connector.cryptography.KeyManagementController;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.connector.cryptography.key.*;
import com.czertainly.cp.soft.exception.NotSupportedException;
import com.czertainly.cp.soft.service.AttributeService;
import com.czertainly.cp.soft.service.KeyManagementService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class KeyManagementControllerImpl implements KeyManagementController {

    private AttributeService attributeService;

    private KeyManagementService keyManagementService;

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Autowired
    public void setKeyManagementService(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }


    @Override
    public List<BaseAttribute> listCreateSecretKeyAttributes(String uuid) throws NotFoundException {
        throw new NotSupportedException("Secret keys are not supported.");
    }

    @Override
    public void validateCreateSecretKeyAttributes(String uuid, List<RequestAttributeDto> attributes) throws NotFoundException, ValidationException {
        throw new NotSupportedException("Secret keys are not supported.");
    }

    @Override
    public SecretKeyDataResponseDto createSecretKey(String uuid, CreateKeyRequestDto request) throws NotFoundException {
        throw new NotSupportedException("Secret keys are not supported.");
    }

    @Override
    public List<BaseAttribute> listCreateKeyPairAttributes(String uuid) throws NotFoundException {
        return attributeService.getCreateKeyAttributes(uuid);
    }

    @Override
    public void validateCreateKeyPairAttributes(String uuid, List<RequestAttributeDto> attributes) throws NotFoundException, ValidationException {
        attributeService.validateCreateKeyAttributes(uuid, attributes);
    }

    @Override
    public KeyPairDataResponseDto createKeyPair(String uuid, CreateKeyRequestDto request) throws NotFoundException {
        return keyManagementService.createKeyPair(UUID.fromString(uuid), request);
    }

    @Override
    public List<KeyDataResponseDto> listKeys(String uuid) throws NotFoundException {
        throw new NotSupportedException("Not implemented.");
    }

    @Override
    public KeyDataResponseDto getKey(String uuid, String keyUuid) throws NotFoundException {
        throw new NotSupportedException("Not implemented.");
    }

    @Override
    public void destroyKey(String uuid, String keyUuid) throws NotFoundException {
        keyManagementService.destroyKey(UUID.fromString(uuid), UUID.fromString(keyUuid));
    }

}
