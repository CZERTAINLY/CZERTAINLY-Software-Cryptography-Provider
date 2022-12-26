package com.czertainly.cp.soft.service;

import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;

import java.util.List;

public interface TokenInstanceService {

    List<TokenInstanceDto> listTokenInstances();

    boolean containsTokens();

}
