package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.stream.Collectors;

public enum DilithiumLevel {
    DILITHIUM_2(2, 10496, 20224),
    DILITHIUM_3(3, 15616, 32000),
    DILITHIUM_5(5, 20736, 38912);

    private static final DilithiumLevel[] VALUES;

    static {
        VALUES = values();
    }

    private final int nistLevel;
    private final int publicKeySize;
    private final int privateKeySize;

    DilithiumLevel(int nistLevel, int publicKeySize, int privateKeySize) {
        this.nistLevel = nistLevel;
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;
    }

    public int getNistLevel() {
        return nistLevel;
    }

    public int getPublicKeySize() {
        return publicKeySize;
    }

    public int getPrivateKeySize() {
        return privateKeySize;
    }

    @Override
    public String toString() {
        return name();
    }

    public static DilithiumLevel valueOf(int nistLevel) {
        DilithiumLevel d = resolve(nistLevel);
        if (d == null) {
            throw new IllegalArgumentException("No matching constant for [" + nistLevel + "]");
        }
        return d;
    }

    @Nullable
    public static DilithiumLevel resolve(int nistLevel) {
        // Use cached VALUES instead of values() to prevent array allocation.
        for (DilithiumLevel d : VALUES) {
            if (d.nistLevel == nistLevel) {
                return d;
            }
        }
        return null;
    }

    public static List<BaseAttributeContent> asIntegerAttributeContentList() {
        return List.of(values()).stream()
                .map(d -> new IntegerAttributeContent(d.name(), d.getNistLevel()))
                .collect(Collectors.toList());
    }
}
