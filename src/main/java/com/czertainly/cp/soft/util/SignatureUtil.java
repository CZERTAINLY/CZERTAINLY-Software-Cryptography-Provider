package com.czertainly.cp.soft.util;

import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.czertainly.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.czertainly.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.attribute.EcdsaKeyAttributes;
import com.czertainly.cp.soft.attribute.RsaKeyAttributes;
import com.czertainly.cp.soft.dao.entity.KeyData;
import com.czertainly.cp.soft.exception.CryptographicOperationException;
import com.czertainly.cp.soft.exception.NotSupportedException;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.slhdsa.BCSLHDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.util.List;

public class SignatureUtil {

    public static Signature prepareSignature(KeyData key, List<RequestAttributeDto> signatureAttributes) {
        String signatureAlgorithm;

        switch (key.getAlgorithm()) {
            case RSA -> {
                final RsaSignatureScheme scheme = RsaSignatureScheme.findByCode(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                                RsaKeyAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME, signatureAttributes, StringAttributeContent.class)
                                .getData()
                );
                final DigestAlgorithm digest = DigestAlgorithm.findByCode(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                                RsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST, signatureAttributes, StringAttributeContent.class)
                                .getData()
                );

                signatureAlgorithm = digest.getProviderName() + "WITHRSA";
                if (scheme == RsaSignatureScheme.PSS) {
                    signatureAlgorithm += "ANDMGF1";
                }

                return getInstanceSignature(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            }
            case ECDSA -> {
                final DigestAlgorithm digest = DigestAlgorithm.findByCode(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                                EcdsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST, signatureAttributes, StringAttributeContent.class)
                                .getData()
                );

                signatureAlgorithm = digest.getProviderName() + "WITHECDSA";

                return getInstanceSignature(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            }
            case FALCON -> {
                return getInstanceSignature("FALCON", BouncyCastlePQCProvider.PROVIDER_NAME);
                /*
                if (key.getLength() == 512) {
                    return getInstanceSignature("Falcon-512", BouncyCastlePQCProvider.PROVIDER_NAME);
                } else {
                    return getInstanceSignature("Falcon-1024", BouncyCastlePQCProvider.PROVIDER_NAME);
                }
                */
            }
            case MLDSA -> {
                signatureAlgorithm = "";
                boolean usePrehash = false;
                if (key.getType() == KeyType.PRIVATE_KEY) {
                    usePrehash = ((CustomKeyValue) key.getValue()).getValues().get("prehash").equals(String.valueOf(true));
                } else {
                    SpkiKeyValue spkiKeyValue = (SpkiKeyValue) key.getValue();
                    BCMLDSAPublicKey bcmldsaPublicKey;
                    try {
                        bcmldsaPublicKey = new BCMLDSAPublicKey(
                                SubjectPublicKeyInfo.getInstance(
                                        Base64.getDecoder().decode(
                                                spkiKeyValue.getValue()
                                        )
                                ));
                    } catch (IOException e) {
                        throw new CryptographicOperationException("Could not create BCMLDSAPublicKey instance from ML-DSA Public Key value: " + spkiKeyValue.getValue());
                    }
                    if (bcmldsaPublicKey.getParameterSpec().getName().contains("WITH")) usePrehash = true;
                }
                if (usePrehash) signatureAlgorithm += "HASH-";
                signatureAlgorithm += "ML-DSA";

                return getInstanceSignature(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            }
            case SLHDSA -> {
                signatureAlgorithm = "";
                boolean usePrehash = false;
                if (key.getType() == KeyType.PRIVATE_KEY) {
                    usePrehash = ((CustomKeyValue) key.getValue()).getValues().get("prehash").equals(String.valueOf(true));
                } else {
                    SpkiKeyValue spkiKeyValue = (SpkiKeyValue) key.getValue();
                    BCSLHDSAPublicKey bcslhdsaPublicKey;
                    try {
                        bcslhdsaPublicKey = new BCSLHDSAPublicKey(
                                SubjectPublicKeyInfo.getInstance(
                                        Base64.getDecoder().decode(
                                                spkiKeyValue.getValue()
                                        )
                                ));
                    } catch (IOException e) {
                        throw new CryptographicOperationException("Could not create BCSLHDSAPublicKey instance from SLH-DSA Public Key value: " + spkiKeyValue.getValue());
                    }
                    if (bcslhdsaPublicKey.getParameterSpec().getName().contains("WITH")) usePrehash = true;
                }
                if (usePrehash) signatureAlgorithm += "HASH-";
                signatureAlgorithm += "SLH-DSA";

                return getInstanceSignature(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            }
            default -> throw new NotSupportedException("Cryptographic algorithm not supported");
        }
    }

    public static Signature getInstanceSignature(String algorithm, String provider) {
        try {
            return Signature.getInstance(algorithm, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Invalid algorithm for signature", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Invalid provider for signature", e);
        }
    }

    public static void initSigning(Signature signature, KeyData key) {
        try {
            signature.initSign(KeyStoreUtil.getPrivateKey(key));
        } catch (InvalidKeyException | UnrecoverableKeyException e) {
            throw new IllegalStateException("Invalid key '"+key.getName()+"'", e);
        }
    }

    public static void initVerification(Signature signature, KeyData key) {
        try {
            signature.initVerify(KeyStoreUtil.getCertificate(key));
        } catch (InvalidKeyException | UnrecoverableKeyException e) {
            throw new IllegalStateException("Invalid key '" + key.getName() + "'", e);
        }
    }

    public static byte[] signData(Signature signature, byte[] data) throws SignatureException {
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifyData(Signature signature, byte[] data, byte[] sign) throws SignatureException {
        signature.update(data);
        return signature.verify(sign);
    }
}
