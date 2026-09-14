package com.inklusport.auth.client;

import com.inklusport.auth.dto.CreateProfileFromRegisterRequest;
import com.inklusport.auth.dto.RecordUserActivityRequest;
import com.inklusport.auth.dto.UserAccessStatusResponse;
import com.inklusport.auth.dto.UserProfileCreatedResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Plan B cuando ink-ms-users no responde.
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
    public java.util.Map<String, String> getUserIdByEmail(String email) {
        log.warn("Users MS no disponible. No se resolvió UUID para {}", email);
        return java.util.Map.of();
    }

    @Override
    public UserAccessStatusResponse getAccessStatus(String email) {
        // Fail-open controlado: si users-ms cae, auth sigue usando su propio isActive.
        log.warn("Users MS no disponible al consultar access-status para {}", email);
        return UserAccessStatusResponse.builder()
                .email(email)
                .allowed(true)
                .active(true)
                .message("Users MS no disponible; se omite verificación remota")
                .build();
    }

    @Override
    public UserProfileCreatedResponse createProfileFromRegister(CreateProfileFromRegisterRequest request) {
        log.error("Users MS no disponible al crear perfil para {}", request.getEmail());
        throw new IllegalStateException(
                "No fue posible crear el perfil de usuario. Intente nuevamente en unos momentos.");
    }

    @Override
    public void recordActivity(RecordUserActivityRequest request) {
        log.warn("Users MS no disponible al registrar actividad {} para {}",
                request != null ? request.getAction() : null,
                request != null ? request.getEmail() : null);
    }
}
