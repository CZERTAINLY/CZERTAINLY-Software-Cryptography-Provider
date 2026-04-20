package com.czertainly.cp.soft.model;

import com.czertainly.api.model.common.attribute.common.MetadataAttribute;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.cryptography.key.value.KeyValue;

import java.util.List;
import java.util.UUID;

/**
 * Immutable, session-detached snapshot of a {@code KeyData} row for the crypto hot path.
 */
public record CachedKeyData(
        UUID uuid,
        UUID tokenInstanceUuid,
        String alias,
        String association,
        KeyType type,
        KeyAlgorithm algorithm,
        KeyFormat format,
        KeyValue value,
        int length,
        List<MetadataAttribute> metadata
) {
}
