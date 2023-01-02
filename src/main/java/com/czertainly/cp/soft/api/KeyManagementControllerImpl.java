package com.czertainly.cp.soft.api;

import com.czertainly.api.exception.KeyManagementException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.interfaces.connector.cryptography.KeyManagementController;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.DestroyKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.KeyDataResponseDto;
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
    public List<BaseAttribute> listCreateKeyAttributes(String uuid) throws NotFoundException {
        return attributeService.getCreateKeyAttributes(uuid);
    }

    @Override
    public void validateCreateKeyAttributes(String uuid, List<RequestAttributeDto> attributes) throws NotFoundException, ValidationException {
        attributeService.validateCreateKeyAttributes(uuid, attributes);
    }

    @Override
    public KeyDataResponseDto createKey(String uuid, CreateKeyRequestDto request) throws NotFoundException, KeyManagementException {
        if (!attributeService.validateCreateKeyAttributes(uuid, request.getCreateKeyAttributes())) {
            throw new ValidationException("Create Key Attributes validation failed.");
        }
        return keyManagementService.createKey(UUID.fromString(uuid), request);
    }

    @Override
    public void destroyKey(String uuid, DestroyKeyRequestDto request) throws NotFoundException, KeyManagementException {
        keyManagementService.destroyKey(UUID.fromString(uuid), request);
    }

}
