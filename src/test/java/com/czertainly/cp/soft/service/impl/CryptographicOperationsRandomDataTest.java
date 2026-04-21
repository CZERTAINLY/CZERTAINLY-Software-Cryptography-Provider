package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.model.connector.cryptography.operations.RandomDataRequestDto;
import com.czertainly.api.model.connector.cryptography.operations.RandomDataResponseDto;
import com.czertainly.cp.soft.service.CryptographicOperationsService;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Transactional
class CryptographicOperationsRandomDataTest extends AbstractCryptographicOperationsTest {

    @Test
    void testRandomData16Bytes() {
        testRandomData(16);
    }

    @Test
    void testRandomData32Bytes() {
        testRandomData(32);
    }

    @Test
    void testRandomData64Bytes() {
        testRandomData(64);
    }

    @Test
    void testRandomData256Bytes() {
        testRandomData(256);
    }

    private void testRandomData(int requestedLength) {
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(requestedLength);

        RandomDataResponseDto response = cryptographicOperationsService.randomData(tokenInstance.getUuid().toString(), request);

        Assertions.assertNotNull(response, "Response should not be null");
        Assertions.assertNotNull(response.getData(), "Response data should not be null");
        Assertions.assertEquals(requestedLength, response.getData().length,
                "Data length should match requested length");
        Assertions.assertFalse(isAllZeros(response.getData()),
                "Data should not be all zeros (probabilistic sanity check)");
    }

    private boolean isAllZeros(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
