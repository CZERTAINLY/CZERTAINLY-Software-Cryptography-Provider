package com.czertainly.cp.soft.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.DestroyKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.KeyDataResponseDto;

import java.util.UUID;

public interface KeyManagementService {

    KeyDataResponseDto createKey(UUID uuid, CreateKeyRequestDto request) throws NotFoundException;

    void destroyKey(UUID uuid, DestroyKeyRequestDto request) throws NotFoundException;

}
