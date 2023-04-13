package com.czertainly.cp.soft.util;

import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.content.BooleanAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.czertainly.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.EncryptDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.data.CipherRequestData;
import com.czertainly.api.model.connector.cryptography.operations.data.CipherResponseData;
import com.czertainly.api.model.core.cryptography.key.OaepHash;
import com.czertainly.api.model.core.cryptography.key.RsaPadding;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.dao.entity.KeyData;
import com.czertainly.cp.soft.exception.NotSupportedException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.*;

public class CipherUtil {
    public static final String ATTRIBUTE_DATA_RSA_PADDING_NAME = "data_rsaPadding";
    public static final String ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME = "data_rsaOaepHash";
    public static final String ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME = "data_rsaOaepMgf";


    public static DecryptDataResponseDto decrypt(CipherDataRequestDto request, KeyData key) {
        List<RequestAttributeDto> attributes = request.getCipherAttributes();
        RsaPadding padding = RsaPadding.findByCode(AttributeDefinitionUtils.getSingleItemAttributeContentValue(ATTRIBUTE_DATA_RSA_PADDING_NAME, attributes, StringAttributeContent.class).getData());
        return decryptData(request, key, getPaddingScheme(padding, request.getCipherAttributes()));
    }

    public static EncryptDataResponseDto encrypt(CipherDataRequestDto request, KeyData key) {
        List<RequestAttributeDto> attributes = request.getCipherAttributes();
        RsaPadding padding = RsaPadding.findByCode(AttributeDefinitionUtils.getSingleItemAttributeContentValue(ATTRIBUTE_DATA_RSA_PADDING_NAME, attributes, StringAttributeContent.class).getData());
        return encryptData(request, key, getPaddingScheme(padding, request.getCipherAttributes()));
    }

    private static String getPaddingScheme(RsaPadding padding, List<RequestAttributeDto> attributes) {
        String paddingScheme;
        if(padding.equals(RsaPadding.PKCS1_v1_5)) {
            paddingScheme = framePkcs1Scheme();
        } else if (padding.equals(RsaPadding.OAEP)) {
            try {
                OaepHash hash = OaepHash.findByCode(AttributeDefinitionUtils.getSingleItemAttributeContentValue(ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME, attributes, StringAttributeContent.class).getData());
                boolean useMgf = AttributeDefinitionUtils.getSingleItemAttributeContentValue(ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME, attributes, BooleanAttributeContent.class).getData();
                paddingScheme = frameOaepPadding(hash, useMgf);
            } catch (Exception e) {
                throw new ValidationException("Invalid attributes for OAEP");
            }
        } else {
            throw new NotSupportedException("Padding type not supported");
        }
        return paddingScheme;
    }

    private static String framePkcs1Scheme() {
        return "RSA/NONE/PKCS1Padding";
    }

    private static String frameOaepPadding(OaepHash hash, boolean useMgf){
        return "RSA/NONE/OAEPWith" + hash.getCode() + (useMgf ? "AndMGF1Padding": "Padding");
    }

    private static DecryptDataResponseDto decryptData(CipherDataRequestDto request, KeyData key, String paddingScheme) {
        DecryptDataResponseDto responseDto = new DecryptDataResponseDto();
        responseDto.setDecryptedData(doProcess(
                request.getCipherData(),
                Cipher.DECRYPT_MODE,
                paddingScheme,
                key
        ));
        return responseDto;
    }

    private static EncryptDataResponseDto encryptData(CipherDataRequestDto request, KeyData key, String paddingScheme) {
        EncryptDataResponseDto responseDto = new EncryptDataResponseDto();
        responseDto.setEncryptedData(doProcess(
                request.getCipherData(),
                Cipher.ENCRYPT_MODE,
                paddingScheme,
                key
        ));
        return responseDto;
    }

    private static List<CipherResponseData> doProcess(List<CipherRequestData> cipherData, int mode, String paddingScheme, KeyData key) {
        Iterator<CipherRequestData> cipherRequestDataIterator = cipherData.stream().iterator();
        List<CipherResponseData> responseDataList = new ArrayList<>();
        while (cipherRequestDataIterator.hasNext()) {
            try {
                byte[] encBytes = cipherRequestDataIterator.next().getData();
                Cipher cipher = Cipher.getInstance(paddingScheme);
                cipher.init(mode, KeyStoreUtil.getPrivateKey(key));

                byte[] decBytes = cipher.doFinal(encBytes);

                CipherResponseData cipherResponseData = new CipherResponseData();
                cipherResponseData.setData(decBytes);
                responseDataList.add(cipherResponseData);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                     IllegalBlockSizeException | BadPaddingException e) {
                throw new ValidationException(ValidationError.create("Exception when decrypting data. Exception is :" + e.getMessage()));
            }
        }
        return responseDataList;
    }
}
