package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.czertainly.cp.soft.attribute.MLKEMAttributes;
import com.czertainly.cp.soft.collection.MLKEMSecurityCategory;
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
    void testGeneratingAndStoringMLKEMKeyPair() throws NotFoundException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        List<RequestAttributeDto> createKeyAttributes = new ArrayList<>();

        String alias = "alias";
        RequestAttributeDto keyAlias = new RequestAttributeDto();
        keyAlias.setName("data_keyAlias");
        keyAlias.setContentType(AttributeContentType.STRING);
        keyAlias.setContent(List.of(new StringAttributeContent(alias)));
        createKeyAttributes.add(keyAlias);

        RequestAttributeDto keyAlgorithm = new RequestAttributeDto();
        keyAlgorithm.setName("data_keyAlgorithm");
        keyAlgorithm.setContentType(AttributeContentType.STRING);

        BaseAttributeContent algorithmContent = new StringAttributeContent();
        algorithmContent.setReference("ML-KEM");
        algorithmContent.setData("ML-KEM");
        keyAlgorithm.setContent(List.of(algorithmContent));
        createKeyAttributes.add(keyAlgorithm);

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

        tokenInstance = tokenInstanceRepository.findByUuid(tokenInstance.getUuid()).get();
        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), PASSWORD);
        Key privateKey;
        Assertions.assertNotNull(privateKey = keyStore.getKey(alias, PASSWORD.toCharArray()));
        Assertions.assertEquals("ML-KEM-768", privateKey.getAlgorithm());
    }
}
