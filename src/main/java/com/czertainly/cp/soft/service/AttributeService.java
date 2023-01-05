package com.czertainly.cp.soft.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;

import java.util.List;
import java.util.UUID;

public interface AttributeService {

    List<BaseAttribute> getAttributes(String kind);

    boolean validateAttributes(String kind, List<RequestAttributeDto> attributes);

    List<BaseAttribute> getTokenInstanceActivationAttributes(String uuid);

    boolean validateTokenInstanceActivationAttributes(String uuid, List<RequestAttributeDto> attributes);

    List<BaseAttribute> getCreateKeyAttributes(String uuid) throws NotFoundException;

    boolean validateCreateKeyAttributes(String uuid, List<RequestAttributeDto> attributes) throws NotFoundException;

    List<BaseAttribute> listSignatureAttributes(UUID uuid, UUID keyUuid) throws NotFoundException;

    boolean validateSignatureAttributes(UUID uuid, UUID keyUuid, List<RequestAttributeDto> attributes) throws NotFoundException;

}
