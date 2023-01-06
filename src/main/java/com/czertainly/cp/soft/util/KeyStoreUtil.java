package com.czertainly.cp.soft.util;

import com.czertainly.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.czertainly.cp.soft.collection.*;
import com.czertainly.cp.soft.dao.entity.KeyData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.DilithiumPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
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
            DilithiumPrivateKey privateKey = (DilithiumPrivateKey) keyStore.getKey(alias, password.toCharArray());
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

    public static void generateDilithiumKey(KeyStore keyStore, String alias, DilithiumLevel level, boolean useAes, String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", BouncyCastlePQCProvider.PROVIDER_NAME);

            String algorithm = "dilithium" + level.getNistLevel();
            if (useAes) {
                algorithm += "-aes";
            }

            kpg.initialize(DilithiumParameterSpec.fromName(algorithm));

            final KeyPair kp = kpg.generateKeyPair();
            final X509Certificate cert = X509Util.generateOrphanX509Certificate(kp, algorithm, BouncyCastlePQCProvider.PROVIDER_NAME);
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Dilithium algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider not found", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid Dilithium algorithm parameters", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate Dilithium key", e);
        }
    }

    public static void generateSphincsPlusKey(KeyStore keyStore, String alias, SphincsPlusHash hash, SphincsPlusParameterSet paramSet, boolean robust, String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", BouncyCastlePQCProvider.PROVIDER_NAME);

            String algorithm = hash.getProviderName() + "-" + paramSet.getParamSet();
            if (robust) {
                algorithm += "-robust";
            } else {
                algorithm += "-simple";
            }

            kpg.initialize(SPHINCSPlusParameterSpec.fromName(algorithm));

            final KeyPair kp = kpg.generateKeyPair();
            final X509Certificate cert = X509Util.generateOrphanX509Certificate(kp, "SPHINCSPlus", BouncyCastlePQCProvider.PROVIDER_NAME);
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SPHINCS+ algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider not found", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid SPHINCS+ algorithm parameters", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate SPHINCS+ key", e);
        }
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
