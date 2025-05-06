package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.content.*;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.czertainly.cp.soft.attribute.KeyAttributes;
import com.czertainly.cp.soft.attribute.MLDSAKeyAttributes;
import com.czertainly.cp.soft.attribute.MLKEMAttributes;
import com.czertainly.cp.soft.attribute.SLHDSAKeyAttributes;
import com.czertainly.cp.soft.collection.*;
import com.czertainly.cp.soft.dao.entity.TokenInstance;
import com.czertainly.cp.soft.dao.repository.TokenInstanceRepository;
import com.czertainly.cp.soft.service.KeyManagementService;
import com.czertainly.cp.soft.util.KeyStoreUtil;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.*;
import java.util.ArrayList;
import java.util.List;

@SpringBootTest
@Transactional
class KeyManagementServiceImplTest {

    public static final String PASSWORD = "123";
    @Autowired
    KeyManagementService keyManagementService;

    @Autowired
    TokenInstanceRepository tokenInstanceRepository;

    TokenInstance tokenInstance;

    @BeforeEach
    void setUp() {
        tokenInstance = new TokenInstance();
        tokenInstance.setCode(PASSWORD);
        tokenInstance.setData(KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD));
        tokenInstanceRepository.save(tokenInstance);
    }

    @Test
    void testMLDSAKey() throws NotFoundException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        String alias = "alias";
        List<RequestAttributeDto> createKeyAttributes = new ArrayList<>(getCreateKeyCommonAttributes(alias, KeyAlgorithm.MLDSA.getCode()));

        RequestAttributeDto mldsaLevel = new RequestAttributeDto();
        mldsaLevel.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL);
        mldsaLevel.setContentType(AttributeContentType.INTEGER);

        IntegerAttributeContent mldsaLevelContent = new IntegerAttributeContent();
        mldsaLevelContent.setReference(MLDSASecurityCategory.MLDSA_44.name());
        mldsaLevelContent.setData(MLDSASecurityCategory.MLDSA_44.getNistSecurityCategory());
        mldsaLevel.setContent(List.of(mldsaLevelContent));
        createKeyAttributes.add(mldsaLevel);

        RequestAttributeDto mldsaUsePrehash = new RequestAttributeDto();
        mldsaUsePrehash.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH);
        mldsaUsePrehash.setContentType(AttributeContentType.BOOLEAN);

        BooleanAttributeContent mldsaUsePrehashContent = new BooleanAttributeContent();
        mldsaUsePrehashContent.setData(false);
        mldsaUsePrehash.setContent(List.of(mldsaUsePrehashContent));
        createKeyAttributes.add(mldsaUsePrehash);

        createKeyRequestDto.setCreateKeyAttributes(createKeyAttributes);

        KeyPairDataResponseDto response = keyManagementService.createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        Assertions.assertEquals(KeyAlgorithm.MLDSA, response.getPrivateKeyData().getKeyData().getAlgorithm());
        Assertions.assertEquals(KeyAlgorithm.MLDSA, response.getPublicKeyData().getKeyData().getAlgorithm());

        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), PASSWORD);
        Key privateKey;
        Assertions.assertNotNull(privateKey = keyStore.getKey(alias, PASSWORD.toCharArray()));
        Assertions.assertEquals("ML-DSA-44", privateKey.getAlgorithm());
    }

    @Test
    void testSLHDSAKey() throws NotFoundException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        String alias = "alias";
        List<RequestAttributeDto> createKeyAttributes = new ArrayList<>(getCreateKeyCommonAttributes(alias, KeyAlgorithm.SLHDSA.getCode()));

        RequestAttributeDto slhdsaSecurityCategory = new RequestAttributeDto();
        slhdsaSecurityCategory.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY);
        slhdsaSecurityCategory.setContentType(AttributeContentType.STRING);

        StringAttributeContent slhdsaLevelContent = new StringAttributeContent();
        slhdsaLevelContent.setReference(SLHDSASecurityCategory.CATEGORY_1.name());
        slhdsaLevelContent.setData(SLHDSASecurityCategory.CATEGORY_1.getNistSecurityCategory());
        slhdsaSecurityCategory.setContent(List.of(slhdsaLevelContent));
        createKeyAttributes.add(slhdsaSecurityCategory);

        RequestAttributeDto slhdsaUsePrehash = new RequestAttributeDto();
        slhdsaUsePrehash.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH);
        slhdsaUsePrehash.setContentType(AttributeContentType.BOOLEAN);

        BooleanAttributeContent slhdsaUsePrehashContent = new BooleanAttributeContent();
        slhdsaUsePrehashContent.setData(true);
        slhdsaUsePrehash.setContent(List.of(slhdsaUsePrehashContent));
        createKeyAttributes.add(slhdsaUsePrehash);

        RequestAttributeDto slhdsaHash = new RequestAttributeDto();
        slhdsaHash.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH);
        slhdsaHash.setContentType(AttributeContentType.STRING);
        slhdsaHash.setContent(List.of(new StringAttributeContent(SLHDSAHash.SHAKE256.name())));
        createKeyAttributes.add(slhdsaHash);

        RequestAttributeDto slhdsaSignatureMode = new RequestAttributeDto();
        slhdsaSignatureMode.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE);
        slhdsaSignatureMode.setContentType(AttributeContentType.STRING);
        slhdsaSignatureMode.setContent(List.of(new StringAttributeContent(SLHDSASignatureMode.FAST.name())));
        createKeyAttributes.add(slhdsaSignatureMode);

        createKeyRequestDto.setCreateKeyAttributes(createKeyAttributes);

        KeyPairDataResponseDto response = keyManagementService.createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        Assertions.assertEquals(KeyAlgorithm.SLHDSA, response.getPrivateKeyData().getKeyData().getAlgorithm());
        Assertions.assertEquals(KeyAlgorithm.SLHDSA, response.getPublicKeyData().getKeyData().getAlgorithm());

        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), PASSWORD);
        Key privateKey;
        Assertions.assertNotNull(privateKey = keyStore.getKey(alias, PASSWORD.toCharArray()));
        Assertions.assertEquals("SLH-DSA-SHAKE-128F-WITH-SHAKE128", privateKey.getAlgorithm());
    }


    @Test
    void testGeneratingAndStoringMLKEMKeyPair() throws NotFoundException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        String alias = "alias";
        List<RequestAttributeDto> createKeyAttributes = new ArrayList<>(getCreateKeyCommonAttributes(alias, KeyAlgorithm.MLKEM.getCode()));

        RequestAttributeDto mlkemLevel = new RequestAttributeDto();
        mlkemLevel.setName(MLKEMAttributes.ATTRIBUTE_DATA_MLKEM_LEVEL);
        mlkemLevel.setContentType(AttributeContentType.INTEGER);

        IntegerAttributeContent mlkemLevelContent = new IntegerAttributeContent();
        mlkemLevelContent.setReference(MLKEMSecurityCategory.CATEGORY_3.name());
        mlkemLevelContent.setData(MLKEMSecurityCategory.CATEGORY_3.getNistSecurityCategory());
        mlkemLevel.setContent(List.of(mlkemLevelContent));
        createKeyAttributes.add(mlkemLevel);

        createKeyRequestDto.setCreateKeyAttributes(createKeyAttributes);

        KeyPairDataResponseDto keyPairDataResponseDto = keyManagementService.createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);
        Assertions.assertEquals(KeyAlgorithm.MLKEM, keyPairDataResponseDto.getPrivateKeyData().getKeyData().getAlgorithm());
        Assertions.assertEquals(KeyAlgorithm.MLKEM, keyPairDataResponseDto.getPublicKeyData().getKeyData().getAlgorithm());

        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), PASSWORD);
        Key privateKey;
        Assertions.assertNotNull(privateKey = keyStore.getKey(alias, PASSWORD.toCharArray()));
        Assertions.assertEquals("ML-KEM-768", privateKey.getAlgorithm());
    }

    List<RequestAttributeDto> getCreateKeyCommonAttributes(String alias, String algorithm) {
        List<RequestAttributeDto> attributes = new ArrayList<>();
        RequestAttributeDto keyAlias = new RequestAttributeDto();
        keyAlias.setName(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS);
        keyAlias.setContentType(AttributeContentType.STRING);
        keyAlias.setContent(List.of(new StringAttributeContent(alias)));
        attributes.add(keyAlias);

        RequestAttributeDto keyAlgorithm = new RequestAttributeDto();
        keyAlgorithm.setName(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM);
        keyAlgorithm.setContentType(AttributeContentType.STRING);

        BaseAttributeContent<String> algorithmContent = new StringAttributeContent();
        algorithmContent.setReference(algorithm);
        algorithmContent.setData(algorithm);
        keyAlgorithm.setContent(List.of(algorithmContent));
        attributes.add(keyAlgorithm);

        return attributes;
    }



}
