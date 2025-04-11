package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;

import java.util.List;
import java.util.stream.Collectors;

public enum SLHDSAHash {
    SHA2("SHA2"),
    SHAKE256("SHAKE")
    ;

    private static final SLHDSAHash[] VALUES;

    static {
        VALUES = values();
    }

    private final String hashName;
    SLHDSAHash(String hashName) {
        this.hashName = hashName;
    }

    public String getHashName() {
        return hashName;
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
