package com.czertainly.cp.soft.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.DestroyKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.KeyPairDataResponseDto;

import java.util.UUID;

public interface KeyManagementService {

    KeyPairDataResponseDto createKeyPair(UUID uuid, CreateKeyRequestDto request) throws NotFoundException;

    void destroyKey(UUID uuid, UUID keyUuid) throws NotFoundException;

}
