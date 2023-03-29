package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.connector.cryptography.enums.KeyType;
import com.czertainly.api.model.connector.cryptography.operations.*;
import com.czertainly.api.model.connector.cryptography.operations.data.*;
import com.czertainly.cp.soft.dao.entity.KeyData;
import com.czertainly.cp.soft.exception.CryptographicOperationException;
import com.czertainly.cp.soft.service.CryptographicOperationsService;
import com.czertainly.cp.soft.service.KeyManagementService;
import com.czertainly.cp.soft.util.DecryptionUtil;
import com.czertainly.cp.soft.util.KeyStoreUtil;
import com.czertainly.cp.soft.util.SecureRandomUtil;
import com.czertainly.cp.soft.util.SignatureUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.*;

@Service
public class CryptographicOperationsServiceImpl implements CryptographicOperationsService {

    private KeyManagementService keyManagementService;

    @Autowired
    public void setKeyManagementService(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    @Override
    public SignDataResponseDto signData(UUID uuid, UUID keyUuid, SignDataRequestDto request) throws NotFoundException {
        // check that the key exists
        // if the key exists, the token instance should exist too
        KeyData key = keyManagementService.getKeyEntity(uuid, keyUuid);

        // check if we are going to sign with private key
        if (key.getType() != KeyType.PRIVATE_KEY) {
            throw new CryptographicOperationException("Only private keys can be used for signing.");
        }

        // initialize signature with the algorithm
        Signature signature = SignatureUtil.prepareSignature(key, request.getSignatureAttributes());

        // initialize the signature with the private key
        SignatureUtil.initSigning(signature, key);

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
        // check that the key exists
        // if the key exists, the token instance should exist too
        KeyData key = keyManagementService.getKeyEntity(uuid, keyUuid);

        // check if we are going to sign with private key
        if (key.getType() != KeyType.PUBLIC_KEY) {
            throw new CryptographicOperationException("Only public keys can be used for verification.");
        }

        // initialize signature with the algorithm
        Signature signature = SignatureUtil.prepareSignature(key, request.getSignatureAttributes());

        // initialize the signature with the private key
        SignatureUtil.initVerification(signature, key);

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

        request.getSignatures().forEach(data -> {

        });

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
        KeyData key = keyManagementService.getKeyEntity(uuid, keyUuid);
        return DecryptionUtil.decrypt(request, key);
    }
}
