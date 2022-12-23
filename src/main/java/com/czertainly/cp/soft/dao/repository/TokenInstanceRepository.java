package com.czertainly.cp.soft.dao.repository;

import com.czertainly.cp.soft.dao.entity.TokenInstance;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TokenInstanceRepository extends JpaRepository<TokenInstance, Long> {

    Optional<TokenInstance> findByName(String name);

    Optional<TokenInstance> findByUuid(String uuid);
}
