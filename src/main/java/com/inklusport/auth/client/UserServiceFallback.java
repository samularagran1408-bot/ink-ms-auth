package com.inklusport.auth.client;

import com.inklusport.auth.dto.CreateProfileFromRegisterRequest;
import com.inklusport.auth.dto.UserProfileCreatedResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Plan B cuando ink-ms-users no responde o el Circuit Breaker se abre.
 * Devuelve el rol USUARIO para que el login no se caiga.
 * El alta de perfil desde registro no tiene fallback silencioso: debe fallar
 * de forma controlada en AuthService para no dejar cuentas sin perfil.
 */
@Component
@Slf4j
public class UserServiceFallback implements UserServiceClient {

    @Override
    public List<String> getUserRoles(String email) {
        log.warn(" Users MS no disponible. Asignando rol USUARIO");
        return List.of("USUARIO");
    }

    @Override
    public UserProfileCreatedResponse createProfileFromRegister(CreateProfileFromRegisterRequest request) {
        log.error("Users MS no disponible al crear perfil para {}", request.getEmail());
        throw new IllegalStateException(
                "No fue posible crear el perfil de usuario. Intente nuevamente en unos momentos.");
    }
}
