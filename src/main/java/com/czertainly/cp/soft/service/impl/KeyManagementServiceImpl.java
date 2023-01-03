package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.attribute.v2.MetadataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.attribute.KeyAttributes;
import com.czertainly.cp.soft.collection.CryptographicAlgorithm;
import com.czertainly.cp.soft.collection.FalconDegree;
import com.czertainly.cp.soft.dao.entity.KeyData;
import com.czertainly.cp.soft.dao.entity.TokenInstance;
import com.czertainly.cp.soft.dao.repository.KeyDataRepository;
import com.czertainly.cp.soft.exception.KeyManagementException;
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

    private KeyDataRepository keyDataRepository;

    @Autowired
    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Autowired
    public void setKeyDataRepository(KeyDataRepository keyDataRepository) {
        this.keyDataRepository = keyDataRepository;
    }

    @Override
    public KeyPairDataResponseDto createKeyPair(UUID uuid, CreateKeyRequestDto request) throws NotFoundException {
        // check if the token exists
        TokenInstance tokenInstance = tokenInstanceService.getTokenInstanceEntity(uuid);

        // load the token
        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), tokenInstance.getCode());

        // generate key inside the keystore
        final String algorithm = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, request.getCreateKeyAttributes(), StringAttributeContent.class).getData();

        CryptographicAlgorithm cryptographicAlgorithm = CryptographicAlgorithm.valueOf(algorithm);

        // alias should be always present for every key
        final String alias = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, request.getCreateKeyAttributes(), StringAttributeContent.class).getData();

        // check if the alias is already used in the keystore
        keyDataRepository.findByNameAndTokenInstanceUuid(alias, uuid)
                .orElseThrow(() -> new KeyManagementException("Alias '" + alias + "'already exists in the KeyStore " + uuid));;

        KeyPairDataResponseDto response = new KeyPairDataResponseDto();

        List<MetadataAttribute> metadata = new ArrayList<>();
        metadata.add(KeyAttributes.buildAliasMetadata(alias));

        switch (cryptographicAlgorithm) {
            case RSA -> {
                final int keySize = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        KeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE, request.getCreateKeyAttributes(), IntegerAttributeContent.class).getData();
                KeyStoreUtil.generateRsaKey(keyStore, alias, keySize, tokenInstance.getCode());

                // add algorithm to the response that complies with the API
                //response.setCryptographicAlgorithm(com.czertainly.api.model.connector.cryptography.enums.CryptographicAlgorithm.RSA);

                // add metadata
                metadata.add(KeyAttributes.buildRsaKeySizeMetadata(keySize));
            }
            case FALCON -> {
                final int degree = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        KeyAttributes.ATTRIBUTE_DATA_FALCON_DEGREE, request.getCreateKeyAttributes(), IntegerAttributeContent.class).getData();
                FalconDegree falconDegree = FalconDegree.resolve(degree);

                KeyStoreUtil.generateFalconKey(keyStore, alias, falconDegree, tokenInstance.getCode());

                // add algorithm to the response that complies with the API
                //response.setCryptographicAlgorithm(com.czertainly.api.model.connector.cryptography.enums.CryptographicAlgorithm.FALCON);

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

        // TODO
        //response.setPrivateKey();
        //response.getPublicKey();

        return response;
    }

    @Override
    public void destroyKey(UUID uuid, UUID keyUuid) throws NotFoundException {

        KeyData key = keyDataRepository.findByUuid(keyUuid)
                .orElseThrow(() -> new NotFoundException(KeyData.class, keyUuid));

        // check if the token exists
        TokenInstance tokenInstance = tokenInstanceService.getTokenInstanceEntity(uuid);

        // load the token
        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), tokenInstance.getCode());

        // metadata must contain alias of the key to be destroyed
        final String alias = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                KeyAttributes.ATTRIBUTE_META_KEY_ALIAS, key.getMetadata(), StringAttributeContent.class).getData();

        // destroy key, it should exists when it is found in the database
        KeyStoreUtil.deleteAliasFromKeyStore(keyStore, alias);

        // store updated token
        byte[] data = KeyStoreUtil.saveKeystore(keyStore, tokenInstance.getCode());
        tokenInstance.setData(data);

        // save token and return
        tokenInstanceService.saveTokenInstance(tokenInstance);

        // delete key from the database
        keyDataRepository.delete(key);
    }

}
