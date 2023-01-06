package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;

import java.util.List;
import java.util.stream.Collectors;

public enum EcdsaCurveName {
    secp192r1(192, "secp192r1", "NIST/SECG curve over a 192 bit prime field"),
    secp224r1(224, "secp224r1", "NIST/SECG curve over a 224 bit prime field"),
    secp256r1(256, "secp256r1", "NIST/SECG curve over a 256 bit prime field"),
    secp384r1(384, "secp384r1", "NIST/SECG curve over a 384 bit prime field"),
    secp521r1(512, "secp521r1", "NIST/SECG curve over a 521 bit prime field");

    private static final EcdsaCurveName[] VALUES;

    static {
        VALUES = values();
    }

    private final int size;

    private final String name;

    private final String description;

    EcdsaCurveName(int size, String name, String description) {
        this.size = size;
        this.name = name;
        this.description = description;
    }

    public int getSize() {
        return size;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return this.name + " " + name();
    }

    public static List<BaseAttributeContent> asStringAttributeContentList() {
        return List.of(values()).stream()
                .map(curve -> new StringAttributeContent(curve.name(), curve.getName()))
                .collect(Collectors.toList());
    }
}
