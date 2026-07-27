package com.inklusport.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class TokenRevocationService {

    private final Map<String, Instant> revokedTokens = new ConcurrentHashMap<>();

    public void revokeToken(String token) {
        if (token == null || token.isBlank()) {
            return;
        }
        revokedTokens.put(token, Instant.now());
        log.info("Token revocado correctamente");
    }

    public boolean isRevoked(String token) {
        if (token == null || token.isBlank()) {
            return true;
        }
        return revokedTokens.containsKey(token);
    }
}
