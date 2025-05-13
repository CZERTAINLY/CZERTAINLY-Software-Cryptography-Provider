package com.czertainly.cp.soft.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.czertainly.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.czertainly.cp.soft.dao.entity.KeyData;

import java.util.List;
import java.util.UUID;

public interface KeyManagementService {

    KeyPairDataResponseDto createKeyPair(UUID uuid, CreateKeyRequestDto request) throws NotFoundException;

    void destroyKey(UUID uuid, UUID keyUuid) throws NotFoundException;

    List<KeyData> listKeyEntities(UUID uuid) throws NotFoundException;

    List<KeyDataResponseDto> listKeys(UUID uuid) throws NotFoundException;

    KeyData getKeyEntity(UUID uuid, UUID keyUuid) throws NotFoundException;

    KeyDataResponseDto getKey(UUID uuid, UUID keyUuid) throws NotFoundException;

}
