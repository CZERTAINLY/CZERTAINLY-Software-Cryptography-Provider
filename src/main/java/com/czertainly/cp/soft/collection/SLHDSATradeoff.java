package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;

import java.util.List;
import java.util.stream.Collectors;

public enum SLHDSATradeoff {

    FAST("f"),
    SHORT("s")
    ;

    private final String parameterName;

    SLHDSATradeoff(String parameterName) {
        this.parameterName = parameterName;
    }

    public String getParameterName() {
        return parameterName;
    }

    public static List<BaseAttributeContent> asStringAttributeContentList() {
        return List.of(values()).stream()
                .map(d -> new StringAttributeContent(d.name()))
                .collect(Collectors.toList());
    }
}
