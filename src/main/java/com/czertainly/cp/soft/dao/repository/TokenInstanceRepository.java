package com.czertainly.cp.soft.dao.repository;

import com.czertainly.cp.soft.dao.entity.TokenInstance;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface TokenInstanceRepository extends JpaRepository<TokenInstance, Long> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<TokenInstance> findByName(String name);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<TokenInstance> findByUuid(UUID uuid);
}
