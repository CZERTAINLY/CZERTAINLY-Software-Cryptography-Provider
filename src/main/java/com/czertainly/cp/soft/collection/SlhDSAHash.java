package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;

import java.util.List;
import java.util.stream.Collectors;

public enum SlhDSAHash {
    SHA2("SHA2", "sha2"),
    SHAKE256("SHAKE256", "shake")
    ;

    private static final SlhDSAHash[] VALUES;

    static {
        VALUES = values();
    }

    private final String hashName;
    private final String providerName;

    SlhDSAHash(String hashName, String providerName) {
        this.hashName = hashName;
        this.providerName = providerName;
    }

    public String getHashName() {
        return hashName;
    }

    public String getProviderName() {
        return providerName;
    }

    @Override
    public String toString() {
        return name();
    }

    public static List<BaseAttributeContent> asStringAttributeContentList() {
        return List.of(values()).stream()
                .map(d -> new StringAttributeContent(d.name(), d.getHashName()))
                .collect(Collectors.toList());
    }
}
