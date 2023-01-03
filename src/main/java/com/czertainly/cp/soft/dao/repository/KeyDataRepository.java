package com.czertainly.cp.soft.dao.repository;

import com.czertainly.cp.soft.dao.entity.KeyData;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface KeyDataRepository extends JpaRepository<KeyData, Long> {

    Optional<KeyData> findByNameAndTokenInstanceUuid(String name, UUID tokenInstanceUuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<KeyData> findByUuid(UUID uuid);
}