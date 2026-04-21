package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.czertainly.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.czertainly.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.czertainly.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.czertainly.cp.soft.attribute.EcdsaKeyAttributes;
import com.czertainly.cp.soft.attribute.KeyAttributes;
import com.czertainly.cp.soft.collection.EcdsaCurveName;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

class CryptographicOperationsEcdsaSignVerifyTest extends AbstractCryptographicOperationsTest {

    @Test
    void testSignVerifyEcdsaSecp256r1Sha256() throws NotFoundException {
        testEcdsaSignVerify(EcdsaCurveName.secp256r1, DigestAlgorithm.SHA_256);
    }

    @Test
    void testSignVerifyEcdsaSecp256r1Sha384() throws NotFoundException {
        testEcdsaSignVerify(EcdsaCurveName.secp256r1, DigestAlgorithm.SHA_384);
    }

    @Test
    void testSignVerifyEcdsaSecp384r1Sha256() throws NotFoundException {
        testEcdsaSignVerify(EcdsaCurveName.secp384r1, DigestAlgorithm.SHA_256);
    }

    @Test
    void testSignVerifyEcdsaSecp384r1Sha384() throws NotFoundException {
        testEcdsaSignVerify(EcdsaCurveName.secp384r1, DigestAlgorithm.SHA_384);
    }

    @Test
    void testSignVerifyEcdsaSecp384r1Sha512() throws NotFoundException {
        testEcdsaSignVerify(EcdsaCurveName.secp384r1, DigestAlgorithm.SHA_512);
    }

    @Test
    void testSignVerifyEcdsaSecp521r1Sha384() throws NotFoundException {
        testEcdsaSignVerify(EcdsaCurveName.secp521r1, DigestAlgorithm.SHA_384);
    }

    @Test
    void testSignVerifyEcdsaSecp521r1Sha512() throws NotFoundException {
        testEcdsaSignVerify(EcdsaCurveName.secp521r1, DigestAlgorithm.SHA_512);
    }

    private void testEcdsaSignVerify(EcdsaCurveName curve, DigestAlgorithm digest) throws NotFoundException {
        // Create key pair
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        createKeyRequestDto.setCreateKeyAttributes(buildEcdsaCreateKeyAttributes("test-ecdsa-" + curve.getName(), curve));

        KeyPairDataResponseDto keyPair = keyManagementService.createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        Assertions.assertEquals(KeyAlgorithm.ECDSA, keyPair.getPrivateKeyData().getKeyData().getAlgorithm());
        Assertions.assertEquals(KeyAlgorithm.ECDSA, keyPair.getPublicKeyData().getKeyData().getAlgorithm());

        UUID privateKeyUuid = UUID.fromString(keyPair.getPrivateKeyData().getUuid());
        UUID publicKeyUuid = UUID.fromString(keyPair.getPublicKeyData().getUuid());

        // Sign
        byte[] plaintext = "Hello, CZERTAINLY!".getBytes();
        SignDataRequestDto signRequest = new SignDataRequestDto();
        signRequest.setSignatureAttributes(buildEcdsaSignatureAttributes(digest));
        signRequest.setData(List.of(new SignatureRequestData(plaintext, "item-1")));

        SignDataResponseDto signResponse = cryptographicOperationsService.signData(
                tokenInstance.getUuid(), privateKeyUuid, signRequest);

        Assertions.assertNotNull(signResponse.getSignatures());
        Assertions.assertEquals(1, signResponse.getSignatures().size());
        byte[] signatureBytes = signResponse.getSignatures().get(0).getData();
        Assertions.assertNotNull(signatureBytes);
        Assertions.assertTrue(signatureBytes.length > 0);
        Assertions.assertNull(signResponse.getSignatures().get(0).getDetails());

        // Verify
        VerifyDataRequestDto verifyRequest = new VerifyDataRequestDto();
        verifyRequest.setSignatureAttributes(buildEcdsaSignatureAttributes(digest));
        verifyRequest.setData(List.of(new SignatureRequestData(plaintext, "item-1")));
        verifyRequest.setSignatures(List.of(new SignatureRequestData(signatureBytes, "item-1")));

        VerifyDataResponseDto verifyResponse = cryptographicOperationsService.verifyData(
                tokenInstance.getUuid(), publicKeyUuid, verifyRequest);

        Assertions.assertNotNull(verifyResponse.getVerifications());
        Assertions.assertEquals(1, verifyResponse.getVerifications().size());
        Assertions.assertTrue(verifyResponse.getVerifications().get(0).isResult());
    }

    private List<RequestAttribute> buildEcdsaCreateKeyAttributes(String alias, EcdsaCurveName curve) {
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(buildAliasAttribute(alias));
        attributes.add(buildAlgorithmAttribute(KeyAlgorithm.ECDSA));

        RequestAttributeV2 curveAttr = new RequestAttributeV2();
        curveAttr.setName(EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE);
        curveAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 curveContent = new StringAttributeContentV2();
        curveContent.setReference(curve.getName());
        curveContent.setData(curve.getName());
        curveAttr.setContent(List.of(curveContent));
        attributes.add(curveAttr);

        return attributes;
    }

    private List<RequestAttribute> buildEcdsaSignatureAttributes(DigestAlgorithm digest) {
        List<RequestAttribute> attributes = new ArrayList<>();

        RequestAttributeV2 digestAttr = new RequestAttributeV2();
        digestAttr.setName(EcdsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST);
        digestAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 digestContent = new StringAttributeContentV2();
        digestContent.setReference(digest.getCode());
        digestContent.setData(digest.getCode());
        digestAttr.setContent(List.of(digestContent));
        attributes.add(digestAttr);

        return attributes;
    }
}
