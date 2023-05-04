package com.czertainly.cp.soft.dao.converter;

import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = true)
public class KeyFormatConverter implements AttributeConverter<KeyFormat, String> {

    @Override
    public String convertToDatabaseColumn(KeyFormat keyFormat) {
        if (keyFormat == null) {
            return null;
        }
        return keyFormat.getCode();
    }

    @Override
    public KeyFormat convertToEntityAttribute(String keyFormat) {
        if (keyFormat == null) {
            return null;
        }
        return KeyFormat.findByCode(keyFormat);
    }

}
