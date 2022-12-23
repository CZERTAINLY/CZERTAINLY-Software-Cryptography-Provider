package com.czertainly.cp.soft.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Component
public class SecretsUtil {

    private static final Logger logger = LoggerFactory.getLogger(SecretsUtil.class);

    @Value("${secrets.encryption.key}")
    private String key;

    private static String encryptionKey;

    @Value("${secrets.encryption.key}")
    public void setEncryptionKeyStatic(String key){
        SecretsUtil.encryptionKey = key;
    }

    /**
     * Encrypts and encodes the given secret using the PBEWithSHA256And256BitAES-CBC-BC algorithm.
     * @param secret the secret to encrypt and encode
     * @param secretVersion the version of the encoding
     * @return the encrypted and encoded secret
     */
    public static String encryptAndEncodeSecretString(String secret, SecretEncodingVersion secretVersion) {
        if (secret == null) {
            return null;
        }

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        byte[] salt = generateRandomSalt();
        int iterations = 1000;

        PBEKeySpec keySpec = new PBEKeySpec(encryptionKey.toCharArray(), salt, iterations);
        String algorithm = "PBEWithSHA256And256BitAES-CBC-BC";
        byte[] encryptedSecret;

        try {
            Cipher c = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            SecretKeyFactory fact = SecretKeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            c.init(Cipher.ENCRYPT_MODE, fact.generateSecret(keySpec));
            encryptedSecret = c.doFinal(secret.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("Padding for " + algorithm + " not found.", e);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException("Illegal block size for " + algorithm, e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + algorithm + " not found", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid specification for " + algorithm, e);
        } catch (BadPaddingException e) {
            throw new IllegalStateException("Bad padding for " + algorithm, e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider not found", e);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Invalid key provided for " + algorithm, e);
        }

        if (secretVersion == SecretEncodingVersion.V1) {
            return encodeSecretStringV1(encryptedSecret, salt, iterations);
        } else {
            throw new IllegalArgumentException("Secret version not supported");
        }

    }

    /**
     * Encoded the secret value into string
     * V1|secret|salt|count
     * @param secret value to be encoded
     * @param salt used salt
     * @param count number of iterations
     * @return encoded string
     */
    private static String encodeSecretStringV1(byte[] secret, byte[] salt, int count) {
        StringBuilder encoded = new StringBuilder();
        encoded.append(SecretEncodingVersion.V1.getVersion());
        encoded.append("|");
        encoded.append(Base64.getEncoder().encodeToString(secret));
        encoded.append("|");
        encoded.append(Base64.getEncoder().encodeToString(salt));
        encoded.append("|");
        encoded.append(count);

        if (logger.isTraceEnabled()) {
            logger.trace("Encoded data: " + encoded.toString());
        }

        return encoded.toString();
    }

    /**
     * Generate random salt for encryption
     * @return salt
     */
    private static byte[] generateRandomSalt() {
        final SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return bytes;
    }

}
