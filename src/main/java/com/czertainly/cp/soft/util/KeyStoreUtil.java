package com.czertainly.cp.soft.util;

import com.czertainly.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.czertainly.cp.soft.collection.*;
import com.czertainly.cp.soft.dao.entity.KeyData;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class KeyStoreUtil {

    public static byte[] createNewKeystore(String type, String code) {
        try {
            KeyStore ks = KeyStore.getInstance(type);
            char[] password = code.toCharArray();
            ks.load(null, password);

            // store the keystore
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ks.store(baos, password);

            return baos.toByteArray();
        } catch (CertificateException e) {
            throw new IllegalStateException("Certificate exception for KeyStore", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Invalid KeyStore ", e);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create new KeyStore", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Invalid algorithm for KeyStore ", e);
        }
    }

    public static byte[] saveKeystore(KeyStore ks, String code) {
        try {
            char[] password = code.toCharArray();
            // store the keystore
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ks.store(baos, password);

            return baos.toByteArray();
        } catch (CertificateException e) {
            throw new IllegalStateException("Certificate exception for KeyStore", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Invalid KeyStore ", e);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create new KeyStore", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Invalid algorithm for KeyStore ", e);
        }
    }

    public static void initKeystore(byte[] data, String code) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            char[] password = code.toCharArray();
            ks.load(new ByteArrayInputStream(data), password);
        } catch (CertificateException e) {
            throw new IllegalStateException("Certificate exception for KeyStore", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Invalid KeyStore ", e);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot instantiate KeyStore", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Invalid algorithm for KeyStore ", e);
        }
    }


    public static KeyStore loadKeystore(byte[] data, String code) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            char[] password = code.toCharArray();
            ks.load(new ByteArrayInputStream(data), password);
            return ks;
        } catch (CertificateException e) {
            throw new IllegalStateException("Certificate exception for KeyStore", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Invalid KeyStore ", e);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot instantiate KeyStore", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Invalid algorithm for KeyStore ", e);
        }
    }

    public static SpkiKeyValue spkiKeyValueFromKeyStore(KeyStore keyStore, String alias) {
        try {
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            return new SpkiKeyValue(Base64.getEncoder().encodeToString(certificate.getPublicKey().getEncoded()));
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot get public key with alias '"+alias+"' from KeyStore", e);
        }
    }

    public static SpkiKeyValue spkiKeyValueFromPrivateKey(KeyStore keyStore, String alias, String password) {
        try {
            MLDSAPrivateKey privateKey = (MLDSAPrivateKey) keyStore.getKey(alias, password.toCharArray());
            return new SpkiKeyValue(Base64.getEncoder().encodeToString(privateKey.getPublicKey().getEncoded()));
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot open KeyStore", e);
        } catch (UnrecoverableKeyException e) {
            throw new IllegalStateException("Cannot get private key with alias '"+alias+"' from KeyStore", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Invalid algorithm", e);
        }
    }

    public static void generateRsaKey(KeyStore keyStore, String alias, int keySize, String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(keySize);
            final KeyPair kp = kpg.generateKeyPair();

            final X509Certificate cert = X509Util.generateRsaOrphanX509Certificate(kp);
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate RSA key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider not found", e);
        }
    }

    public static void generateEcdsaKey(KeyStore keyStore, String alias, EcdsaCurveName curveName, String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec(curveName.name()));
            final KeyPair kp = kpg.generateKeyPair();

            final X509Certificate cert = X509Util.generateEcdsaOrphanX509Certificate(kp);
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate ECDSA key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("ECDSA algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider not found", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid curve name `"+curveName.getName()+"`", e);
        }
    }

    public static void generateFalconKey(KeyStore keyStore, String alias, FalconDegree degree, String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon", "BCPQC");

            if (degree == FalconDegree.FALCON_512) {
                kpg.initialize(FalconParameterSpec.falcon_512);
            } else if (degree == FalconDegree.FALCON_1024) {
                kpg.initialize(FalconParameterSpec.falcon_1024);
            } else {
                throw new IllegalStateException("Invalid Falcon degree");
            }

            final KeyPair kp = kpg.generateKeyPair();
            final X509Certificate cert;

            if (degree == FalconDegree.FALCON_512) {
                cert = X509Util.generateFalconOrphanX509Certificate(kp, FalconDegree.FALCON_512);
            } else {
                cert = X509Util.generateFalconOrphanX509Certificate(kp, FalconDegree.FALCON_1024);
            }
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Falcon algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider not found", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid Falcon algorithm parameters", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate Falcon key", e);
        }
    }

    public static void generateMLDSAKey(KeyStore keyStore, String alias, MLDSASecurityCategory level, String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME);

            String algorithm = "ML-DSA-" + level.getParameterSet();

            kpg.initialize(MLDSAParameterSpec.fromName(algorithm));

            final KeyPair kp = kpg.generateKeyPair();
            final X509Certificate cert = X509Util.generateOrphanX509Certificate(kp, algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("ML-DSA algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider not found", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid ML-DSA algorithm parameters", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate ML-DSA key", e);
        }
    }

    public static void generateSlhDsaKey(KeyStore keyStore, String alias, SlhDSAHash hash, SlhDsaSecurityCategory securityCategory, SlhDsaTradeoff tradeoff, String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", BouncyCastleProvider.PROVIDER_NAME);

            String algorithm = buildSlhDsaParameterSpec(hash, securityCategory, tradeoff);

            kpg.initialize(SLHDSAParameterSpec.fromName(algorithm));

            final KeyPair kp = kpg.generateKeyPair();
            final X509Certificate cert = X509Util.generateOrphanX509Certificate(kp, "SLH-DSA", BouncyCastleProvider.PROVIDER_NAME);
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SLH-DSA algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider not found", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid SLH-DSA algorithm parameters", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate SLH-DSA key", e);
        }
    }

    private static String buildSlhDsaParameterSpec(SlhDSAHash hash, SlhDsaSecurityCategory securityCategory, SlhDsaTradeoff tradeoff) {
        String algorithm = "SLH-DSA-";
        if (hash == SlhDSAHash.SHA2) {
            algorithm += "SHA2-";
        } else {
            algorithm += "SHAKE-";
        }
        if (securityCategory == SlhDsaSecurityCategory.CATEGORY_1) {
            algorithm += "128";
        } else if (securityCategory == SlhDsaSecurityCategory.CATEGORY_3) {
            algorithm += "192";
        } else {
            algorithm += "256";
        }

        if (tradeoff == SlhDsaTradeoff.SHORT) {
            algorithm += "s";
        } else {
            algorithm += "f";
        }
        return algorithm;
    }

    public static void deleteAliasFromKeyStore(KeyStore keyStore, String alias) {
        try {
            keyStore.deleteEntry(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot remove alias '" + alias + "'", e);
        }
    }

    public static PrivateKey getPrivateKey(KeyData key) {
        KeyStore keyStore = loadKeystore(key.getTokenInstance().getData(), key.getTokenInstance().getCode());
        try {
            return (PrivateKey) keyStore.getKey(key.getName(), key.getTokenInstance().getCode().toCharArray());
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot load Token '"+key.getTokenInstance().getName()+"'", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm '"+key.getAlgorithm()+"' cannot be used", e);
        } catch (UnrecoverableKeyException e) {
            throw new IllegalStateException("Cannot load private key '"+key.getName()+"' from Token '"+key.getTokenInstance().getName()+"'", e);
        }
    }

    public static X509Certificate getCertificate(KeyData key) {
        KeyStore keyStore = loadKeystore(key.getTokenInstance().getData(), key.getTokenInstance().getCode());
        try {
            return (X509Certificate) keyStore.getCertificate(key.getName());
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot load Token '"+key.getTokenInstance().getName()+"'", e);
        }
    }

}
