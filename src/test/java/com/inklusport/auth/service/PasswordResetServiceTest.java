package com.inklusport.auth.service;

import com.inklusport.auth.config.InvalidResetTokenException;
import com.inklusport.auth.dto.ForgotPasswordRequest;
import com.inklusport.auth.dto.ForgotPasswordResponse;
import com.inklusport.auth.entity.AuthUser;
import com.inklusport.auth.entity.PasswordResetToken;
import com.inklusport.auth.repository.AuthUserRepository;
import com.inklusport.auth.repository.PasswordResetTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock
    private AuthUserRepository authUserRepository;
    @Mock
    private PasswordResetTokenRepository tokenRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private EmailService emailService;

    @InjectMocks
    private PasswordResetService passwordResetService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(passwordResetService, "tokenExpiryMinutes", 10);
    }

    @Test
    void forgotPassword_emailDesconocidoNoEnviaCorreo() {
        ForgotPasswordRequest request = new ForgotPasswordRequest();
        request.setEmail("nadie@inklusport.test");
        when(authUserRepository.findByEmail(request.getEmail())).thenReturn(Optional.empty());

        ForgotPasswordResponse response = passwordResetService.forgotPassword(request);

        assertTrue(response.getMessage().contains("Si el email está registrado"));
        assertNull(response.getResetToken());
        verify(emailService, never()).sendPasswordResetCode(anyString(), anyString(), anyInt());
        verify(tokenRepository, never()).save(any());
    }

    @Test
    void forgotPassword_emailRegistradoGeneraCodigo() {
        ForgotPasswordRequest request = new ForgotPasswordRequest();
        request.setEmail("ana@inklusport.test");
        AuthUser user = new AuthUser();
        user.setId("user-1");
        user.setEmail(request.getEmail());
        when(authUserRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(user));

        ForgotPasswordResponse response = passwordResetService.forgotPassword(request);

        assertNotNull(response.getResetToken());
        assertTrue(response.getResetToken().matches("\\d{6}"));
        verify(tokenRepository).save(any(PasswordResetToken.class));
        verify(emailService).sendPasswordResetCode(eq("ana@inklusport.test"), anyString(), eq(10));
    }

    @Test
    void verifyResetCode_rechazaCodigoInvalidoOExpirado() {
        when(tokenRepository.findByTokenAndUsedFalse("000000")).thenReturn(Optional.empty());
        assertThrows(InvalidResetTokenException.class, () -> passwordResetService.verifyResetCode("000000"));

        PasswordResetToken expired = new PasswordResetToken();
        expired.setToken("123456");
        expired.setUsed(false);
        expired.setExpiresAt(LocalDateTime.now().minusMinutes(1));
        when(tokenRepository.findByTokenAndUsedFalse("123456")).thenReturn(Optional.of(expired));

        InvalidResetTokenException error = assertThrows(
                InvalidResetTokenException.class,
                () -> passwordResetService.verifyResetCode("123456")
        );
        assertTrue(error.getMessage().contains("expirado"));
    }
}
