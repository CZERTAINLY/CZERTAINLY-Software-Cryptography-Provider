package com.czertainly.cp.soft.util;

import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.czertainly.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.EncryptDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.data.CipherRequestData;
import com.czertainly.api.model.connector.cryptography.operations.data.CipherResponseData;
import com.czertainly.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.attribute.RsaCipherAttributes;
import com.czertainly.cp.soft.exception.NotSupportedException;
import com.czertainly.cp.soft.model.CachedKeyData;
import com.czertainly.cp.soft.model.CachedKeyMaterial;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.*;

public class CipherUtil {

    public static DecryptDataResponseDto decrypt(CipherDataRequestDto request, CachedKeyData key, CachedKeyMaterial material) {
        switch (key.algorithm()) {
            case RSA -> {
                List<RequestAttribute> attributes = request.getCipherAttributes();
                RsaEncryptionScheme rsaEncryptionScheme = RsaEncryptionScheme.findByCode(AttributeDefinitionUtils.getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME, attributes, StringAttributeContentV2.class).getData());
                return decryptData(request, key, material, getCipherTransformation(rsaEncryptionScheme, request.getCipherAttributes()));
            }
            default -> throw new NotSupportedException("Algorithm not supported");
        }
    }

    public static EncryptDataResponseDto encrypt(CipherDataRequestDto request, CachedKeyData key, CachedKeyMaterial material) {
        switch (key.algorithm()) {
            case RSA -> {
                List<RequestAttribute> attributes = request.getCipherAttributes();
                RsaEncryptionScheme rsaEncryptionScheme = RsaEncryptionScheme.findByCode(AttributeDefinitionUtils.getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME, attributes, StringAttributeContentV2.class).getData());
                return encryptData(request, key, material, getCipherTransformation(rsaEncryptionScheme, request.getCipherAttributes()));
            }
            default -> throw new NotSupportedException("Algorithm not supported");
        }
    }

    private static DecryptDataResponseDto decryptData(CipherDataRequestDto request, CachedKeyData key, CachedKeyMaterial material, String transformation) {
        DecryptDataResponseDto responseDto = new DecryptDataResponseDto();
        responseDto.setDecryptedData(doProcess(request.getCipherData(), Cipher.DECRYPT_MODE, transformation, key, material));
        return responseDto;
    }

    private static EncryptDataResponseDto encryptData(CipherDataRequestDto request, CachedKeyData key, CachedKeyMaterial material, String transformation) {
        EncryptDataResponseDto responseDto = new EncryptDataResponseDto();
        responseDto.setEncryptedData(doProcess(request.getCipherData(), Cipher.ENCRYPT_MODE, transformation, key, material));
        return responseDto;
    }

    private static List<CipherResponseData> doProcess(List<CipherRequestData> cipherData, int mode,
                                                      String transformation, CachedKeyData key, CachedKeyMaterial material) {
        Iterator<CipherRequestData> it = cipherData.stream().iterator();
        List<CipherResponseData> responseDataList = new ArrayList<>();
        while (it.hasNext()) {
            try {
                byte[] encBytes = it.next().getData();
                Cipher cipher = Cipher.getInstance(transformation);
                cipher.init(mode, KeyStoreUtil.getPrivateKey(key, material));
                CipherResponseData cipherResponseData = new CipherResponseData();
                cipherResponseData.setData(cipher.doFinal(encBytes));
                responseDataList.add(cipherResponseData);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                     IllegalBlockSizeException | BadPaddingException e) {
                throw new ValidationException(ValidationError.create("Exception when processing cipher data: " + e.getMessage()));
            }
        }
        return responseDataList;
    }

    private static String getCipherTransformation(RsaEncryptionScheme rsaEncryptionScheme, List<RequestAttribute> attributes) {
        String transformation;
        if (rsaEncryptionScheme.equals(RsaEncryptionScheme.PKCS1_v1_5)) {
            transformation = framePkcs1Scheme();
        } else if (rsaEncryptionScheme.equals(RsaEncryptionScheme.OAEP)) {
            try {
                DigestAlgorithm hash = DigestAlgorithm.findByCode(AttributeDefinitionUtils.getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME, attributes, StringAttributeContentV2.class).getData());
                boolean useMgf = AttributeDefinitionUtils.getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME, attributes, BooleanAttributeContentV2.class).getData();
                transformation = frameOaepTransformation(hash, useMgf);
            } catch (Exception e) {
                throw new ValidationException("Invalid attributes for OAEP");
            }
        } else {
            throw new NotSupportedException("Transformation type not supported");
        }
        return transformation;
    }

    private static String framePkcs1Scheme() {
        return "RSA/NONE/PKCS1Padding";
    }

    private static String frameOaepTransformation(DigestAlgorithm hash, boolean useMgf) {
        return "RSA/NONE/OAEPWith" + hash.getProviderName() + (useMgf ? "AndMGF1Padding" : "Padding");
    }
}
