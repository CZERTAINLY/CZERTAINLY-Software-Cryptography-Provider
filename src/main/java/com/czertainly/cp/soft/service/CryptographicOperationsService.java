package com.czertainly.cp.soft.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.connector.cryptography.operations.*;

import java.util.UUID;

public interface CryptographicOperationsService {

    SignDataResponseDto signData(UUID uuid, UUID keyUuid, SignDataRequestDto request) throws NotFoundException;

    VerifyDataResponseDto verifyData(UUID uuid, UUID keyUuid, VerifyDataRequestDto request) throws NotFoundException;

    RandomDataResponseDto randomData(String uuid, RandomDataRequestDto request);

    DecryptDataResponseDto decryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request) throws NotFoundException;

}
