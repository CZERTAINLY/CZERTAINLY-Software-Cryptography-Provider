package com.czertainly.cp.soft.api;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.interfaces.connector.cryptography.CryptographicOperationsController;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.connector.cryptography.operations.*;
import com.czertainly.cp.soft.exception.NotSupportedException;
import com.czertainly.cp.soft.service.AttributeService;
import com.czertainly.cp.soft.service.CryptographicOperationsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class CryptographicOperationsControllerImpl implements CryptographicOperationsController {

    private CryptographicOperationsService cryptographicOperationsService;

    private AttributeService attributeService;

    @Autowired
    public void setCryptographicOperationsService(CryptographicOperationsService cryptographicOperationsService) {
        this.cryptographicOperationsService = cryptographicOperationsService;
    }

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Override
    public EncryptDataResponseDto encryptData(String uuid, String keyUuid, CipherDataRequestDto request) throws NotFoundException {
        return cryptographicOperationsService.encryptData(UUID.fromString(uuid), UUID.fromString(keyUuid), request);
    }

    @Override
    public DecryptDataResponseDto decryptData(String uuid, String keyUuid, CipherDataRequestDto request) throws NotFoundException {
        return cryptographicOperationsService.decryptData(UUID.fromString(uuid), UUID.fromString(keyUuid), request);
    }

    @Override
    public SignDataResponseDto signData(String uuid, String keyUuid, SignDataRequestDto request) throws NotFoundException {
        return cryptographicOperationsService.signData(UUID.fromString(uuid), UUID.fromString(keyUuid), request);
    }

    @Override
    public VerifyDataResponseDto verifyData(String uuid, String keyUuid, VerifyDataRequestDto request) throws NotFoundException {
        return cryptographicOperationsService.verifyData(UUID.fromString(uuid), UUID.fromString(keyUuid), request);
    }

    @Override
    public List<BaseAttribute> listRandomAttributes(String uuid) throws NotFoundException {
        return List.of();
    }

    @Override
    public void validateRandomAttributes(String uuid, List<RequestAttributeDto> attributes) throws NotFoundException, ValidationException {
        // nothing to validate
    }

    @Override
    public RandomDataResponseDto randomData(String uuid, RandomDataRequestDto request) throws NotFoundException {
        return cryptographicOperationsService.randomData(uuid, request);
    }

}
