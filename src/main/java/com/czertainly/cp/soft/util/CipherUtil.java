package com.czertainly.cp.soft.util;

import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.content.BooleanAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.czertainly.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.EncryptDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.data.CipherRequestData;
import com.czertainly.api.model.connector.cryptography.operations.data.CipherResponseData;
import com.czertainly.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.attribute.RsaCipherAttributes;
import com.czertainly.cp.soft.dao.entity.KeyData;
import com.czertainly.cp.soft.exception.NotSupportedException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.*;

public class CipherUtil {

    public static DecryptDataResponseDto decrypt(CipherDataRequestDto request, KeyData key) {
        switch (key.getAlgorithm()) {
            case RSA -> {
                List<RequestAttributeDto> attributes = request.getCipherAttributes();
                RsaEncryptionScheme rsaEncryptionScheme = RsaEncryptionScheme.findByCode(AttributeDefinitionUtils.getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME, attributes, StringAttributeContent.class).getData());
                return decryptData(request, key, getCipherTransformation(rsaEncryptionScheme, request.getCipherAttributes()));
            }
            default -> throw new NotSupportedException("Algorithm not supported");
        }
    }

    public static EncryptDataResponseDto encrypt(CipherDataRequestDto request, KeyData key) {
        switch (key.getAlgorithm()) {
            case RSA -> {
                List<RequestAttributeDto> attributes = request.getCipherAttributes();
                RsaEncryptionScheme rsaEncryptionScheme = RsaEncryptionScheme.findByCode(AttributeDefinitionUtils.getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME, attributes, StringAttributeContent.class).getData());
                return encryptData(request, key, getCipherTransformation(rsaEncryptionScheme, request.getCipherAttributes()));
            }
            default -> throw new NotSupportedException("Algorithm not supported");
        }
    }

    private static String getCipherTransformation(RsaEncryptionScheme rsaEncryptionScheme, List<RequestAttributeDto> attributes) {
        String transformation;
        if(rsaEncryptionScheme.equals(RsaEncryptionScheme.PKCS1_v1_5)) {
            transformation = framePkcs1Scheme();
        } else if (rsaEncryptionScheme.equals(RsaEncryptionScheme.OAEP)) {
            try {
                DigestAlgorithm hash = DigestAlgorithm.findByCode(AttributeDefinitionUtils.getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME, attributes, StringAttributeContent.class).getData());
                boolean useMgf = AttributeDefinitionUtils.getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME, attributes, BooleanAttributeContent.class).getData();
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

    private static String frameOaepTransformation(DigestAlgorithm hash, boolean useMgf){
        return "RSA/NONE/OAEPWith" + hash.getProviderName() + (useMgf ? "AndMGF1Padding": "Padding");
    }

    private static DecryptDataResponseDto decryptData(CipherDataRequestDto request, KeyData key, String transformation) {
        DecryptDataResponseDto responseDto = new DecryptDataResponseDto();
        responseDto.setDecryptedData(doProcess(
                request.getCipherData(),
                Cipher.DECRYPT_MODE,
                transformation,
                key
        ));
        return responseDto;
    }

    private static EncryptDataResponseDto encryptData(CipherDataRequestDto request, KeyData key, String transformation) {
        EncryptDataResponseDto responseDto = new EncryptDataResponseDto();
        responseDto.setEncryptedData(doProcess(
                request.getCipherData(),
                Cipher.ENCRYPT_MODE,
                transformation,
                key
        ));
        return responseDto;
    }

    private static List<CipherResponseData> doProcess(List<CipherRequestData> cipherData, int mode, String transformation, KeyData key) {
        Iterator<CipherRequestData> cipherRequestDataIterator = cipherData.stream().iterator();
        List<CipherResponseData> responseDataList = new ArrayList<>();
        while (cipherRequestDataIterator.hasNext()) {
            try {
                byte[] encBytes = cipherRequestDataIterator.next().getData();
                Cipher cipher = Cipher.getInstance(transformation);
                cipher.init(mode, KeyStoreUtil.getPrivateKey(key));

                byte[] decBytes = cipher.doFinal(encBytes);

                CipherResponseData cipherResponseData = new CipherResponseData();
                cipherResponseData.setData(decBytes);
                responseDataList.add(cipherResponseData);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                     IllegalBlockSizeException | BadPaddingException | UnrecoverableKeyException e) {
                throw new ValidationException(ValidationError.create("Exception when decrypting data. Exception is :" + e.getMessage()));
            }
        }
        return responseDataList;
    }
}
