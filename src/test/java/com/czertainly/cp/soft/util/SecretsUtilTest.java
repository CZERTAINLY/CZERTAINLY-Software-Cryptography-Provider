package com.czertainly.cp.soft.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class SecretsUtilTest {

    private static String secret = "This is my secret value I want to protect";

    @Test
    public void testEncodeSecret_ok() {
        String encodedSecret = SecretsUtil.encryptAndEncodeSecretString(secret, SecretEncodingVersion.V1);

        Assertions.assertEquals(encodedSecret.substring(0, 2), SecretEncodingVersion.V1.getVersion());
    }

}
