package com.inklusport.auth.service;

import com.inklusport.auth.client.UserServiceClient;
import com.inklusport.auth.config.EmailAlreadyRegisteredException;
import com.inklusport.auth.dto.AuthResponse;
import com.inklusport.auth.dto.LoginRequest;
import com.inklusport.auth.dto.RegisterRequest;
import com.inklusport.auth.dto.UserAccessStatusResponse;
import com.inklusport.auth.dto.UserProfileCreatedResponse;
import com.inklusport.auth.entity.AuthUser;
import com.inklusport.auth.repository.AuthUserRepository;
import com.inklusport.auth.repository.LoginAttemptRepository;
import com.inklusport.auth.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthUserRepository authUserRepository;
    @Mock
    private LoginAttemptRepository loginAttemptRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtTokenProvider jwtTokenProvider;
    @Mock
    private UserServiceClient userServiceClient;
    @Mock
    private GoogleTokenVerifier googleTokenVerifier;

    @InjectMocks
    private AuthService authService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "maxAttempts", 5);
        ReflectionTestUtils.setField(authService, "blockDurationMinutes", 15);
    }

    @Test
    void register_rechazaEmailDuplicado() {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("ya@existe.test");
        request.setNombre("Ana");
        request.setPassword("secret1");
        when(authUserRepository.existsByEmail("ya@existe.test")).thenReturn(true);

        assertThrows(EmailAlreadyRegisteredException.class, () -> authService.register(request, "127.0.0.1"));
        verify(authUserRepository, never()).save(any());
    }

    @Test
    void register_creaPerfilYDevuelveToken() {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("nuevo@inklusport.test");
        request.setNombre("Ana");
        request.setPassword("secret1");

        when(authUserRepository.existsByEmail(request.getEmail())).thenReturn(false);
        when(passwordEncoder.encode("secret1")).thenReturn("hash");
        when(userServiceClient.createProfileFromRegister(any()))
                .thenReturn(UserProfileCreatedResponse.builder()
                        .id("user-1")
                        .email(request.getEmail())
                        .fullName("Ana")
                        .build());
        when(jwtTokenProvider.generateToken(eq(request.getEmail()), anyList())).thenReturn("jwt-token");

        AuthResponse response = authService.register(request, "127.0.0.1");

        assertEquals("jwt-token", response.getToken());
        assertEquals("Bearer", response.getTipo());
        assertEquals(request.getEmail(), response.getEmail());
        verify(authUserRepository).save(any(AuthUser.class));
    }

    @Test
    void login_rechazaPasswordIncorrecta() {
        LoginRequest request = new LoginRequest();
        request.setEmail("ana@inklusport.test");
        request.setPassword("mala");

        AuthUser user = new AuthUser();
        user.setEmail(request.getEmail());
        user.setPasswordHash("hash");
        user.setIsActive(true);

        when(loginAttemptRepository.countRecentFailuresByEmail(eq(request.getEmail()), any())).thenReturn(0L);
        when(loginAttemptRepository.countRecentFailuresByIp(eq("127.0.0.1"), any())).thenReturn(0L);
        when(authUserRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("mala", "hash")).thenReturn(false);

        RuntimeException error = assertThrows(RuntimeException.class, () -> authService.login(request, "127.0.0.1"));
        assertEquals("Credenciales inválidas", error.getMessage());
        verify(jwtTokenProvider, never()).generateToken(anyString(), anyList());
    }

    @Test
    void login_generaTokenConRolesDeUsersMs() {
        LoginRequest request = new LoginRequest();
        request.setEmail("ana@inklusport.test");
        request.setPassword("secret1");

        AuthUser user = new AuthUser();
        user.setEmail(request.getEmail());
        user.setPasswordHash("hash");
        user.setIsActive(true);

        when(loginAttemptRepository.countRecentFailuresByEmail(eq(request.getEmail()), any())).thenReturn(0L);
        when(loginAttemptRepository.countRecentFailuresByIp(eq("127.0.0.1"), any())).thenReturn(0L);
        when(authUserRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret1", "hash")).thenReturn(true);
        when(userServiceClient.getAccessStatus(request.getEmail()))
                .thenReturn(UserAccessStatusResponse.builder().allowed(true).build());
        when(userServiceClient.getUserRoles(request.getEmail())).thenReturn(List.of("USUARIO"));
        when(jwtTokenProvider.generateToken(request.getEmail(), List.of("USUARIO"))).thenReturn("jwt-ok");

        AuthResponse response = authService.login(request, "127.0.0.1");

        assertEquals("jwt-ok", response.getToken());
        verify(authUserRepository).updateLastLogin(eq(request.getEmail()), any());
    }

    @Test
    void login_bloqueaPorFuerzaBruta() {
        LoginRequest request = new LoginRequest();
        request.setEmail("ana@inklusport.test");
        request.setPassword("secret1");
        when(loginAttemptRepository.countRecentFailuresByEmail(eq(request.getEmail()), any())).thenReturn(5L);

        RuntimeException error = assertThrows(RuntimeException.class, () -> authService.login(request, "127.0.0.1"));
        assertTrue(error.getMessage().contains("Demasiados intentos fallidos"));
        verify(authUserRepository, never()).findByEmail(anyString());
    }
}
