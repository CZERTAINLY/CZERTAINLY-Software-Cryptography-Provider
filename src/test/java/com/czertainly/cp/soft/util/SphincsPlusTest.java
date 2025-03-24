package com.czertainly.cp.soft.util;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.*;

@SpringBootTest
public class SphincsPlusTest {

    @Test
    public void testSphincsPlus() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", BouncyCastlePQCProvider.PROVIDER_NAME);

        KeyPair kp = kpg.generateKeyPair();

        kpg.initialize(SPHINCSPlusParameterSpec.sha2_128f);

        KeyPair kpRes = kpg.generateKeyPair();

        System.out.println(kpRes.getPrivate());

    }

}
