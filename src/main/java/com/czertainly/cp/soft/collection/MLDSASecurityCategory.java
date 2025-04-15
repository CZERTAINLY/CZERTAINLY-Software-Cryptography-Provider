package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.stream.Collectors;

public enum MLDSASecurityCategory {
    MLDSA_44(2, 10496, 20480, "44"),
    MLDSA_65(3, 15616, 32256, "65"),
    MLDSA_87(5, 20736, 39168, "87");

    private static final MLDSASecurityCategory[] VALUES;

    static {
        VALUES = values();
    }

    private final int nistSecurityCategory;
    private final int publicKeySize;
    private final int privateKeySize;
    private final String parameterSet;

    MLDSASecurityCategory(int nistLevel, int publicKeySize, int privateKeySize, String parameterSet) {
        this.nistSecurityCategory = nistLevel;
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;
        this.parameterSet = parameterSet;
    }

    public int getNistSecurityCategory() {
        return nistSecurityCategory;
    }

    public int getPublicKeySize() {
        return publicKeySize;
    }

    public int getPrivateKeySize() {
        return privateKeySize;
    }

    public String getParameterSet() {return parameterSet;}

    @Override
    public String toString() {
        return name();
    }

    public static MLDSASecurityCategory valueOf(int nistLevel) {
        MLDSASecurityCategory d = resolve(nistLevel);
        if (d == null) {
            throw new IllegalArgumentException("No matching constant for [" + nistLevel + "]");
        }
        return d;
    }

    @Nullable
    public static MLDSASecurityCategory resolve(int nistLevel) {
        // Use cached VALUES instead of values() to prevent array allocation.
        for (MLDSASecurityCategory d : VALUES) {
            if (d.nistSecurityCategory == nistLevel) {
                return d;
            }
        }
        return null;
    }

    public static List<BaseAttributeContent> asIntegerAttributeContentList() {
        return List.of(values()).stream()
                .map(d -> new IntegerAttributeContent(d.name(), d.getNistSecurityCategory()))
                .collect(Collectors.toList());
    }
}
