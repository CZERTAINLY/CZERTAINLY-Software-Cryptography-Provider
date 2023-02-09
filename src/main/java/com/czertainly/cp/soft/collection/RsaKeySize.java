package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.IntegerAttributeContent;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.stream.Collectors;

public enum RsaKeySize {
    RSA_1024(1024),
    RSA_2048(2048),
    RSA_4096(4096);

    private static final RsaKeySize[] VALUES;

    static {
        VALUES = values();
    }

    private final int size;

    RsaKeySize(int size) {
        this.size = size;
    }

    public int getSize() {
        return size;
    }

    @Override
    public String toString() {
        return this.size + " " + name();
    }

    public static RsaKeySize valueOf(int size) {
        RsaKeySize alg = resolve(size);
        if (alg == null) {
            throw new IllegalArgumentException("No matching constant for [" + size + "]");
        }
        return alg;
    }

    @Nullable
    public static RsaKeySize resolve(int size) {
        // Use cached VALUES instead of values() to prevent array allocation.
        for (RsaKeySize alg : VALUES) {
            if (alg.size == size) {
                return alg;
            }
        }
        return null;
    }

    public static List<BaseAttributeContent> asIntegerAttributeContentList() {
        return List.of(values()).stream()
                .map(size -> new IntegerAttributeContent(size.name(), size.getSize()))
                .collect(Collectors.toList());
    }
}
