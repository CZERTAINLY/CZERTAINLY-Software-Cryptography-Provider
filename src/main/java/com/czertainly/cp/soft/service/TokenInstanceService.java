package com.czertainly.cp.soft.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceRequestDto;

import java.util.List;
import java.util.UUID;

public interface TokenInstanceService {

    List<TokenInstanceDto> listTokenInstances();

    TokenInstanceDto getTokenInstance(UUID uuid) throws NotFoundException;

    TokenInstanceDto createTokenInstance(TokenInstanceRequestDto request) throws AlreadyExistException;

    boolean containsTokens();

}
