package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum SLHDSASignatureMode {

    FAST("f"),
    SMALL("s")
    ;

    private final String parameterName;

    SLHDSASignatureMode(String parameterName) {
        this.parameterName = parameterName;
    }

    public String getParameterName() {
        return parameterName;
    }

    public static List<BaseAttributeContent> asStringAttributeContentList() {
        return Stream.of(values())
                .map(d -> new StringAttributeContent(d.name()))
                .collect(Collectors.toList());
    }
}
