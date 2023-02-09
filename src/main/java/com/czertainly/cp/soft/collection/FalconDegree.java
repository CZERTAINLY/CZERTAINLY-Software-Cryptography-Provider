package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.stream.Collectors;

public enum FalconDegree {
    FALCON_512(512, 7176, 10088),
    FALCON_1024(1024, 14344, 18440);

    private static final FalconDegree[] VALUES;

    static {
        VALUES = values();
    }

    private final int degree;
    private final int publicKeySize;
    private final int privateKeySize;

    FalconDegree(int degree, int publicKeySize, int privateKeySize) {
        this.degree = degree;
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;
    }

    public int getDegree() {
        return degree;
    }

    public int getPublicKeySize() {
        return publicKeySize;
    }

    public int getPrivateKeySize() {
        return privateKeySize;
    }

    @Override
    public String toString() {
        return this.degree + " " + name();
    }

    public static FalconDegree valueOf(int degree) {
        FalconDegree d = resolve(degree);
        if (d == null) {
            throw new IllegalArgumentException("No matching constant for [" + degree + "]");
        }
        return d;
    }

    @Nullable
    public static FalconDegree resolve(int degree) {
        // Use cached VALUES instead of values() to prevent array allocation.
        for (FalconDegree d : VALUES) {
            if (d.degree == degree) {
                return d;
            }
        }
        return null;
    }

    public static List<BaseAttributeContent> asIntegerAttributeContentList() {
        return List.of(values()).stream()
                .map(degree -> new IntegerAttributeContent(degree.name(), degree.getDegree()))
                .collect(Collectors.toList());
    }
}
