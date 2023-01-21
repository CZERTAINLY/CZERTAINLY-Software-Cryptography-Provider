package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;

import java.util.List;
import java.util.stream.Collectors;

public enum SphincsPlusParameterSet {
    S_128("128s", 256, 512),
    F_128("128f", 256, 512),
    S_192("192s", 384, 768),
    F_192("192f", 384, 768),
    S_256("256s", 512, 1024),
    F_256("256f", 512, 1024);

    private static final SphincsPlusParameterSet[] VALUES;

    static {
        VALUES = values();
    }

    private final String paramSet;
    private final int publicKeySize;
    private final int privateKeySize;

    SphincsPlusParameterSet(String paramSet, int publicKeySize, int privateKeySize) {
        this.paramSet = paramSet;
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;
    }

    public String getParamSet() {
        return paramSet;
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

    public static List<BaseAttributeContent> asStringAttributeContentList() {
        return List.of(values()).stream()
                .map(d -> new StringAttributeContent(d.name(), d.getParamSet()))
                .collect(Collectors.toList());
    }
}
