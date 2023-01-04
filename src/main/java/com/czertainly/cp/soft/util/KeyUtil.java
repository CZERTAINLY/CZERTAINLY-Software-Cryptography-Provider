package com.czertainly.cp.soft.util;

import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.connector.cryptography.key.value.KeyValue;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

public class KeyUtil {

    private static final ObjectMapper ATTRIBUTES_OBJECT_MAPPER = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public static String serializeKeyValue(KeyValue keyValue) {
        if (keyValue == null) {
            return null;
        }
        try {
            return ATTRIBUTES_OBJECT_MAPPER.writeValueAsString(keyValue);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static <T extends KeyValue> T deserializeKeyValue(String keyValue, Class<T> clazz) {
        if (keyValue == null) {
            return null;
        }
        try {
            return ATTRIBUTES_OBJECT_MAPPER.readValue(keyValue, clazz);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

}
