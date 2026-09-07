package com.inklusport.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Mantiene en memoria los tokens JWT revocados (p. ej. al cerrar sesión).
 */
@Service
@Slf4j
public class TokenRevocationService {

    private final Map<String, Instant> revokedTokens = new ConcurrentHashMap<>();

    /**
     * Añade el token a la lista de revocados. Ignora valores nulos o vacíos.
     */
    public void revokeToken(String token) {
        if (token == null || token.isBlank()) {
            return;
        }
        revokedTokens.put(token, Instant.now());
        log.info("Token revocado correctamente");
    }

    /**
     * Indica si el token está revocado o es nulo/vacío.
     */
    public boolean isRevoked(String token) {
        if (token == null || token.isBlank()) {
            return true;
        }
        return revokedTokens.containsKey(token);
    }
}
