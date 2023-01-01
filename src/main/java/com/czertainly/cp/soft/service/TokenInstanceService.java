package com.czertainly.cp.soft.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.TokenInstanceException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceRequestDto;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceStatusDto;
import com.czertainly.cp.soft.dao.entity.TokenInstance;

import java.util.List;
import java.util.UUID;

public interface TokenInstanceService {

    List<TokenInstanceDto> listTokenInstances();

    TokenInstanceDto getTokenInstance(UUID uuid) throws NotFoundException;

    TokenInstance getTokenInstanceEntity(UUID uuid) throws NotFoundException;

    TokenInstanceDto createTokenInstance(TokenInstanceRequestDto request) throws AlreadyExistException, TokenInstanceException;

    void removeTokenInstance(UUID uuid) throws NotFoundException;

    TokenInstanceStatusDto getTokenInstanceStatus(UUID uuid) throws NotFoundException;

    void activateTokenInstance(UUID uuid, List<RequestAttributeDto> attributes) throws NotFoundException, TokenInstanceException;

    void deactivateTokenInstance(UUID uuid) throws NotFoundException, TokenInstanceException;

    boolean containsTokens();

    void saveTokenInstance(TokenInstance tokenInstance);

}
