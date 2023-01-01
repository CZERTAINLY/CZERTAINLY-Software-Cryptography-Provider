package com.czertainly.cp.soft.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

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


}
