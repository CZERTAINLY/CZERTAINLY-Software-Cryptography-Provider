package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;

import java.util.List;
import java.util.stream.Collectors;

public enum SlhDsaSecurityCategory {
    CATEGORY_1("1", 256, 512),
    CATEGORY_3("3", 384, 768),
    CATEGORY_5("5", 512, 1024)
    ;

    private static final SlhDsaSecurityCategory[] VALUES;

    static {
        VALUES = values();
    }

    private final String nistSecurityCategory;
    private final int publicKeySize;
    private final int privateKeySize;

    SlhDsaSecurityCategory(String nistSecurityCategory, int publicKeySize, int privateKeySize) {
        this.nistSecurityCategory = nistSecurityCategory;
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;

    }

    public String getNistSecurityCategory() {
        return nistSecurityCategory;
    }

    public int getPublicKeySize() {
        return publicKeySize;
    }

    public int getPrivateKeySize() {
        return privateKeySize;
    }

    @Override
    public String toString() {
        return nistSecurityCategory;
    }

    public static List<BaseAttributeContent> asStringAttributeContentList() {
        return List.of(values()).stream()
                .map(d -> new StringAttributeContent(d.name(), d.getNistSecurityCategory()))
                .collect(Collectors.toList());
    }
}
