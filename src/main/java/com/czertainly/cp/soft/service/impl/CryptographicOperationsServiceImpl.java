package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.cryptography.operations.*;
import com.czertainly.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.czertainly.api.model.connector.cryptography.operations.data.SignatureResponseData;
import com.czertainly.api.model.connector.cryptography.operations.data.VerificationResponseData;
import com.czertainly.cp.soft.exception.CryptographicOperationException;
import com.czertainly.cp.soft.service.CryptographicOperationsService;
import com.czertainly.cp.soft.service.KeyDataCacheService;
import com.czertainly.cp.soft.service.KeyStoreCacheService;
import com.czertainly.cp.soft.model.CachedKeyData;
import com.czertainly.cp.soft.model.CachedKeyMaterial;
import com.czertainly.cp.soft.util.CipherUtil;
import com.czertainly.cp.soft.util.SecureRandomUtil;
import com.czertainly.cp.soft.util.SignatureUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

@Service
public class CryptographicOperationsServiceImpl implements CryptographicOperationsService {
    private KeyDataCacheService keyDataCacheService;
    private KeyStoreCacheService keyStoreCacheService;

    @Override
    public SignDataResponseDto signData(UUID uuid, UUID keyUuid, SignDataRequestDto request) throws NotFoundException {
        CachedKeyData key = keyDataCacheService.getCachedKeyData(keyUuid);

        // check if we are going to sign with private key
        if (key.type() != KeyType.PRIVATE_KEY) {
            throw new CryptographicOperationException("Only private keys can be used for signing.");
        }

        CachedKeyMaterial material = keyStoreCacheService.loadKeyMaterial(key.tokenInstanceUuid());
        // initialize signature with the algorithm
        Signature signature = SignatureUtil.prepareSignature(key, request.getSignatureAttributes());
        // initialize the signature with the private key
        SignatureUtil.initSigning(signature, key, material);

        // sign the data, it can be a list, so we need to iterate over it
        SignDataResponseDto response = new SignDataResponseDto();
        List<SignatureResponseData> signatures = new ArrayList<>();

        request.getData().forEach(data -> {
            SignatureResponseData signatureResponseData = new SignatureResponseData();
            signatureResponseData.setIdentifier(data.getIdentifier());
            try {
                signatureResponseData.setData(SignatureUtil.signData(signature, data.getData()));
            } catch (SignatureException e) {
                signatureResponseData.setDetails("Signature failed: " + e.getMessage());
            }
            signatures.add(signatureResponseData);
        });

        response.setSignatures(signatures);
        return response;
    }

    @Override
    public VerifyDataResponseDto verifyData(UUID uuid, UUID keyUuid, VerifyDataRequestDto request) throws NotFoundException {
        CachedKeyData key = keyDataCacheService.getCachedKeyData(keyUuid);

        // check if we are going to verify with public key
        if (key.type() != KeyType.PUBLIC_KEY) {
            throw new CryptographicOperationException("Only public keys can be used for verification.");
        }

        CachedKeyMaterial material = keyStoreCacheService.loadKeyMaterial(key.tokenInstanceUuid());
        // initialize signature with the algorithm
        Signature signature = SignatureUtil.prepareSignature(key, request.getSignatureAttributes());
        // initialize the signature with the private key
        SignatureUtil.initVerification(signature, key, material);

        // verify the data, it can be a list, so we need to iterate over it
        VerifyDataResponseDto response = new VerifyDataResponseDto();
        List<VerificationResponseData> verifications = new ArrayList<>();

        Iterator<SignatureRequestData> signIterator = request.getSignatures().iterator();
        Iterator<SignatureRequestData> dataIterator = request.getData().iterator();

        while (dataIterator.hasNext() && signIterator.hasNext()) {
            SignatureRequestData sign = signIterator.next();
            SignatureRequestData data = dataIterator.next();

            VerificationResponseData verificationResponseData = new VerificationResponseData();
            verificationResponseData.setIdentifier(sign.getIdentifier());
            try {
                verificationResponseData.setResult(SignatureUtil.verifyData(signature, data.getData(), sign.getData()));
            } catch (SignatureException e) {
                verificationResponseData.setDetails("Verification failed: " + e.getMessage());
            }
            verifications.add(verificationResponseData);
        }

        response.setVerifications(verifications);
        return response;
    }

    @Override
    public RandomDataResponseDto randomData(String uuid, RandomDataRequestDto request) {
        SecureRandom secureRandom = SecureRandomUtil.prepareSecureRandom("DEFAULT", BouncyCastleProvider.PROVIDER_NAME);
        byte[] bytes = new byte[request.getLength()];
        secureRandom.nextBytes(bytes);

        RandomDataResponseDto response = new RandomDataResponseDto();
        response.setData(bytes);
        return response;
    }

    @Override
    public DecryptDataResponseDto decryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request) throws NotFoundException {
        CachedKeyData key = keyDataCacheService.getCachedKeyData(keyUuid);
        CachedKeyMaterial material = keyStoreCacheService.loadKeyMaterial(key.tokenInstanceUuid());
        return CipherUtil.decrypt(request, key, material);
    }

    @Override
    public EncryptDataResponseDto encryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request) throws NotFoundException {
        CachedKeyData key = keyDataCacheService.getCachedKeyData(keyUuid);
        CachedKeyMaterial material = keyStoreCacheService.loadKeyMaterial(key.tokenInstanceUuid());
        return CipherUtil.encrypt(request, key, material);
    }

    @Autowired
    public void setKeyDataCacheService(KeyDataCacheService keyDataCacheService) {
        this.keyDataCacheService = keyDataCacheService;
    }

    @Autowired
    public void setKeyStoreCacheService(KeyStoreCacheService keyStoreCacheService) {
        this.keyStoreCacheService = keyStoreCacheService;
    }
}
