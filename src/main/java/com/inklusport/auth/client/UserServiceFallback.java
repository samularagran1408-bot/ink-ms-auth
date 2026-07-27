package com.inklusport.auth.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Plan B cuando ink-ms-users no responde o el Circuit Breaker se abre.
 * Devuelve el rol USUARIO para que el login no se caiga.
 */
@Component
@Slf4j
public class UserServiceFallback implements UserServiceClient {

    @Override
    public List<String> getUserRoles(String email) {
        log.warn(" Users MS no disponible. Asignando rol USUARIO");
        return List.of("USUARIO");
    }
}
