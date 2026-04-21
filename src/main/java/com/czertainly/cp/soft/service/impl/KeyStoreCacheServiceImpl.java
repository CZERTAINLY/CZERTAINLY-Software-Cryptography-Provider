package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.cp.soft.config.CacheConfig;
import com.czertainly.cp.soft.dao.entity.TokenInstance;
import com.czertainly.cp.soft.dao.repository.TokenInstanceRepository;
import com.czertainly.cp.soft.exception.TokenInstanceException;
import com.czertainly.cp.soft.service.KeyStoreCacheService;
import com.czertainly.cp.soft.model.CachedKeyMaterial;
import com.czertainly.cp.soft.util.KeyStoreUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class KeyStoreCacheServiceImpl implements KeyStoreCacheService {
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreCacheServiceImpl.class);

    private final CacheManager cacheManager;
    private final TokenInstanceRepository tokenInstanceRepository;

    public KeyStoreCacheServiceImpl(CacheManager cacheManager,
                                    TokenInstanceRepository tokenInstanceRepository) {
        this.cacheManager = cacheManager;
        this.tokenInstanceRepository = tokenInstanceRepository;
    }

    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = CacheConfig.KEYSTORES_CACHE, key = "#tokenInstanceUuid", sync = true)
    public CachedKeyMaterial loadKeyMaterial(UUID tokenInstanceUuid) throws NotFoundException {
        logger.debug("Cache miss — loading key material for token instance {} from database",
                tokenInstanceUuid);

        TokenInstance tokenInstance = tokenInstanceRepository.findByUuid(tokenInstanceUuid)
                .orElseThrow(() -> new NotFoundException(TokenInstance.class, tokenInstanceUuid));

        String code = tokenInstance.getCode();
        if (code == null) {
            throw new TokenInstanceException("Token is not activated.");
        }

        KeyStore ks = KeyStoreUtil.loadKeystore(tokenInstance.getData(), code);

        Map<String, PrivateKey> privateKeys = new HashMap<>();
        Map<String, PublicKey>  publicKeys  = new HashMap<>();

        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                try {
                    Key key = ks.getKey(alias, code.toCharArray());
                    if (key instanceof PrivateKey pk) {
                        privateKeys.put(alias, pk);
                    }
                } catch (UnrecoverableKeyException | NoSuchAlgorithmException e) {
                    logger.debug("Skipping alias '{}' — cannot recover key: {}", alias, e.getMessage());
                }

                Certificate cert = ks.getCertificate(alias);
                if (cert != null) {
                    publicKeys.put(alias, cert.getPublicKey());
                }
            }
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot enumerate KeyStore aliases", e);
        }

        return new CachedKeyMaterial(
                Collections.unmodifiableMap(privateKeys),
                Collections.unmodifiableMap(publicKeys)
        );
    }

    /**
     * Schedules cache eviction to run after the current transaction commits.
     *
     * <p><b>Consistency guarantee (eventual, not strict):</b> eviction fires in the {@code afterCommit} phase of Spring's
     * transaction synchronization, which runs <em>after</em> the database row has already been made visible to other transactions.</p>
     *
     * <p>In the narrow window between commit and the synchronization callback, a concurrent reader <em>could</em> repopulate
     * the cache with the newly-written value — which is correct — rather than the stale value. This is benign (the cached value
     * is never stale-after-eviction, only potentially refreshed a few microseconds early), but callers should not assume
     * strict linearizability between writes and cache state.</p>
     */
    @Override
    public void evictAfterCommit(UUID tokenInstanceUuid) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    doEvict(tokenInstanceUuid);
                }
            });
        } else {
            logger.debug("evictAfterCommit called outside a transaction for token instance {}; evicting immediately", tokenInstanceUuid);
            doEvict(tokenInstanceUuid);
        }
    }

    private void doEvict(UUID tokenInstanceUuid) {
        Cache cache = cacheManager.getCache(CacheConfig.KEYSTORES_CACHE);
        if (cache != null) {
            cache.evict(tokenInstanceUuid);
            logger.debug("Evicted cached key material for token instance {}", tokenInstanceUuid);
        }
    }
}
