package com.czertainly.cp.soft.dao.converter;

import com.czertainly.api.model.connector.cryptography.enums.CryptographicAlgorithm;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = true)
public class CryptographicAlgorithmConverter implements AttributeConverter<CryptographicAlgorithm, String> {

    @Override
    public String convertToDatabaseColumn(CryptographicAlgorithm cryptographicAlgorithm) {
        if (cryptographicAlgorithm == null) {
            return null;
        }
        return cryptographicAlgorithm.name();
    }

    @Override
    public CryptographicAlgorithm convertToEntityAttribute(String cryptographicAlgorithm) {
        if (cryptographicAlgorithm == null) {
            return null;
        }
        return CryptographicAlgorithm.valueOf(cryptographicAlgorithm);
    }

}
