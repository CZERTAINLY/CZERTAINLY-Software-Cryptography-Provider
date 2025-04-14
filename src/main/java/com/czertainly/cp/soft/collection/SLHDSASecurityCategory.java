package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum SLHDSASecurityCategory {
    CATEGORY_1("1", 256, 512, "128"),
    CATEGORY_3("3", 384, 768, "192"),
    CATEGORY_5("5", 512, 1024, "256")
    ;

    private static final SLHDSASecurityCategory[] VALUES;

    static {
        VALUES = values();
    }

    private final String nistSecurityCategory;
    private final int publicKeySize;
    private final int privateKeySize;
    private final String securityParameterLength;


    SLHDSASecurityCategory(String nistSecurityCategory, int publicKeySize, int privateKeySize, String securityParameterLength) {
        this.nistSecurityCategory = nistSecurityCategory;
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;
        this.securityParameterLength = securityParameterLength;
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

    public String getSecurityParameterLength() {
        return securityParameterLength;
    }

    @Override
    public String toString() {
        return nistSecurityCategory;
    }

    public static List<BaseAttributeContent> asStringAttributeContentList() {
        return Stream.of(values())
                .map(d -> new StringAttributeContent(d.name(), d.getNistSecurityCategory()))
                .collect(Collectors.toList());
    }
}
