package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.DestroyKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.attribute.KeyAttributes;
import com.czertainly.cp.soft.collection.CryptographicAlgorithm;
import com.czertainly.cp.soft.collection.FalconDegree;
import com.czertainly.cp.soft.dao.entity.TokenInstance;
import com.czertainly.cp.soft.service.KeyManagementService;
import com.czertainly.cp.soft.service.TokenInstanceService;
import com.czertainly.cp.soft.util.KeyStoreUtil;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class KeyManagementServiceImpl implements KeyManagementService {

    private TokenInstanceService tokenInstanceService;

    @Autowired
    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Override
    public KeyDataResponseDto createKey(UUID uuid, CreateKeyRequestDto request) throws NotFoundException {
        // check if the token exists
        TokenInstance tokenInstance = tokenInstanceService.getTokenInstanceEntity(uuid);

        // load the token
        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), tokenInstance.getCode());

        // TODO: check if the key with alias already exists

        // generate key inside the keystore
        final String algorithm = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, request.getCreateKeyAttributes(), StringAttributeContent.class).getData();

        CryptographicAlgorithm cryptographicAlgorithm = CryptographicAlgorithm.valueOf(algorithm);

        // alias should be always present for every key
        final String alias = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, request.getCreateKeyAttributes(), StringAttributeContent.class).getData();

        KeyDataResponseDto response = new KeyDataResponseDto();

        List<MetadataAttribute> metadata = new ArrayList<>();
        metadata.add(KeyAttributes.buildAliasMetadata(alias));

        switch (cryptographicAlgorithm) {
            case RSA -> {
                final int keySize = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        KeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE, request.getCreateKeyAttributes(), IntegerAttributeContent.class).getData();
                KeyStoreUtil.generateRsaKey(keyStore, alias, keySize, tokenInstance.getCode());

                // add algorithm to the response that complies with the API
                response.setCryptographicAlgorithm(com.czertainly.api.model.connector.cryptography.enums.CryptographicAlgorithm.RSA);

                // add metadata
                metadata.add(KeyAttributes.buildRsaKeySizeMetadata(keySize));
            }
            case FALCON -> {
                final int degree = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        KeyAttributes.ATTRIBUTE_DATA_FALCON_DEGREE, request.getCreateKeyAttributes(), IntegerAttributeContent.class).getData();
                FalconDegree falconDegree = FalconDegree.resolve(degree);

                KeyStoreUtil.generateFalconKey(keyStore, alias, falconDegree, tokenInstance.getCode());

                // add algorithm to the response that complies with the API
                response.setCryptographicAlgorithm(com.czertainly.api.model.connector.cryptography.enums.CryptographicAlgorithm.FALCON);

                // add metadata
                metadata.add(KeyAttributes.buildFalconDegreeMetadata(degree));

            }
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }

        // store key inside token
        byte[] data = KeyStoreUtil.saveKeystore(keyStore, tokenInstance.getCode());
        tokenInstance.setData(data);

        // save token and return
        tokenInstanceService.saveTokenInstance(tokenInstance);

        response.setKeyAttributes(metadata);
        return response;
    }

    @Override
    public void destroyKey(UUID uuid, DestroyKeyRequestDto request) throws NotFoundException {
        // check if the token exists
        TokenInstance tokenInstance = tokenInstanceService.getTokenInstanceEntity(uuid);

        // load the token
        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), tokenInstance.getCode());

        // metadata must contain alias of the key to be destroyed
        final String alias = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                KeyAttributes.ATTRIBUTE_META_KEY_ALIAS, request.getKeyAttributes(), StringAttributeContent.class).getData();

        // destroy key
        KeyStoreUtil.deleteAliasFromKeyStore(keyStore, alias);

        // store key inside token
        byte[] data = KeyStoreUtil.saveKeystore(keyStore, tokenInstance.getCode());
        tokenInstance.setData(data);

        // save token and return
        tokenInstanceService.saveTokenInstance(tokenInstance);
    }

}
