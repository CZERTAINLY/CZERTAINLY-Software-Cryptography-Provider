package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.cp.soft.dao.entity.TokenInstance;
import com.czertainly.cp.soft.dao.repository.TokenInstanceRepository;
import com.czertainly.cp.soft.service.TokenInstanceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class TokenInstanceServiceImpl implements TokenInstanceService {

    private TokenInstanceRepository tokenInstanceRepository;

    @Autowired
    public void setTokenInstanceRepository(TokenInstanceRepository tokenInstanceRepository) {
        this.tokenInstanceRepository = tokenInstanceRepository;
    }

    @Override
    public List<TokenInstanceDto> listTokenInstances() {
        List<TokenInstance> tokens;
        tokens = tokenInstanceRepository.findAll();
        if (!tokens.isEmpty()) {
            return tokens
                    .stream().map(TokenInstance::mapToDto)
                    .collect(Collectors.toList());
        }
        return null;
    }

    @Override
    public boolean containsTokens() {
        return listTokenInstances() != null;
    }

}
