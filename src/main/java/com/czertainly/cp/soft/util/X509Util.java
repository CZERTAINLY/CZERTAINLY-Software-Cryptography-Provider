package com.czertainly.cp.soft.util;

import com.czertainly.cp.soft.collection.FalconDegree;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class X509Util {

    public static X509Certificate generateRsaOrphanX509Certificate(KeyPair keyPair) {;
        return generateOrphanX509Certificate(keyPair, "SHA512WithRSAEncryption");
    }

    public static X509Certificate generateFalconOrphanX509Certificate(KeyPair keyPair, FalconDegree degree) {
        if (degree == FalconDegree.FALCON_512) {
            return generateOrphanX509Certificate(keyPair, "Falcon-512");
        } else if (degree == FalconDegree.FALCON_1024) {
            return generateOrphanX509Certificate(keyPair, "Falcon-1024");
        } else {
            throw new IllegalArgumentException("Unknown Falcon degree");
        }
    }

    public static X509Certificate generateOrphanX509Certificate(KeyPair keyPair, String signatureAlgorithm) {;
        SecureRandom random = new SecureRandom();

        X500Name owner = new X500Name("CN=generatedCertificate,O=orphan");

        // current time minus 1 year, just in case software clock goes back due to time synchronization
        final Date notBefore = new Date(System.currentTimeMillis() - 86400000L * 365);
        final Date notAfter = new Date(System.currentTimeMillis() + 86400000L * 365 * 30); // 30 years from now

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                owner, new BigInteger( 64, random ), notBefore, notAfter, owner, keyPair.getPublic() );

        PrivateKey privateKey = keyPair.getPrivate();

        try {
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);

            X509CertificateHolder certHolder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider())
                    .getCertificate(certHolder);

            //check so that cert is valid
            cert.verify(keyPair.getPublic());

            return cert;
        } catch (CertificateException e) {
            throw new IllegalStateException("Error reading the certificate", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Invalid algorithm", e);
        } catch (SignatureException e) {
            throw new IllegalStateException("Error building the signature ", e);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Operator cannot be created", e);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Invalid key pair", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider not found", e);
        }
    }

}
