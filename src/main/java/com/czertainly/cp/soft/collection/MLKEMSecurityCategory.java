package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.stream.Collectors;

public enum MLKEMSecurityCategory {

    CATEGORY_1(1, 6400, 13056, "ML-KEM-512"),
    CATEGORY_3(3, 9472, 19200, "ML-KEM-768"),
    CATEGORY_5(5, 12544, 253444, "ML-KEM-1024")
    ;

    private static final MLKEMSecurityCategory[] VALUES;

    static {
        VALUES = values();
    }

    private final int nistSecurityCategory;
    private final int publicKeySize;
    private final int privateKeySize;
    private final String parameterSet;

    MLKEMSecurityCategory(int nistLevel, int publicKeySize, int privateKeySize, String parameterSet) {
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

    public static MLKEMSecurityCategory valueOf(int nistLevel) {
        MLKEMSecurityCategory d = resolve(nistLevel);
        if (d == null) {
            throw new IllegalArgumentException("No matching constant for [" + nistLevel + "]");
        }
        return d;
    }

    @Nullable
    public static MLKEMSecurityCategory resolve(int nistLevel) {
        // Use cached VALUES instead of values() to prevent array allocation.
        for (MLKEMSecurityCategory d : VALUES) {
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
