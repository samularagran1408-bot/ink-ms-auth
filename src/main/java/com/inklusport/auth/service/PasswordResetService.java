package com.inklusport.auth.service;

import com.inklusport.auth.config.InvalidResetTokenException;
import com.inklusport.auth.dto.ForgotPasswordRequest;
import com.inklusport.auth.dto.ResetPasswordRequest;
import com.inklusport.auth.dto.ForgotPasswordResponse;
import com.inklusport.auth.dto.ResetPasswordResponse;
import com.inklusport.auth.entity.AuthUser;
import com.inklusport.auth.entity.PasswordResetToken;
import com.inklusport.auth.repository.AuthUserRepository;
import com.inklusport.auth.repository.PasswordResetTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;

/**
 * Gestiona la solicitud, verificación y restablecimiento de contraseña.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordResetService {

    private final AuthUserRepository authUserRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Value("${app.password-reset.token-expiry-minutes:10}")
    private int tokenExpiryMinutes;

    private static final SecureRandom random = new SecureRandom();

    /**
     * Genera y envía un código de recuperación si el email está registrado.
     */
    @Transactional
    public ForgotPasswordResponse forgotPassword(ForgotPasswordRequest request) {
        String resetToken = null;
        AuthUser user = authUserRepository.findByEmail(request.getEmail()).orElse(null);

        if (user != null) {
            tokenRepository.deleteByUserId(user.getId());

            resetToken = generateSixDigitCode();
            
            PasswordResetToken token = new PasswordResetToken();
            token.setUserId(user.getId());
            token.setToken(resetToken);
            token.setExpiresAt(LocalDateTime.now().plusMinutes(tokenExpiryMinutes));
            token.setUsed(false);

            tokenRepository.save(token);
            log.info("Código de recuperación generado para: {}", user.getEmail());
            
            emailService.sendPasswordResetCode(user.getEmail(), resetToken, tokenExpiryMinutes);
        } else {
            log.info("Solicitud de recuperación para email no registrado: {}", request.getEmail());
        }

        return ForgotPasswordResponse.builder()
                .message("Si el email está registrado, recibirás un código de 6 dígitos para restablecer tu contraseña.")
                .resetToken(resetToken) 
                .build();
    }

    /**
     * Comprueba que el código de recuperación sea válido y no esté expirado.
     */
    @Transactional(readOnly = true)
    public void verifyResetCode(String code) {
        requireValidToken(code);
    }

    /**
     * Restablece la contraseña con un código válido y lo marca como usado.
     */
    @Transactional
    public ResetPasswordResponse resetPassword(ResetPasswordRequest request) {
        PasswordResetToken token = requireValidToken(request.getToken());

        AuthUser user = authUserRepository.findById(token.getUserId())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        authUserRepository.save(user);

        token.setUsed(true);
        tokenRepository.save(token);

        log.info("Contraseña restablecida para usuario: {}", user.getEmail());

        return ResetPasswordResponse.builder()
                .message("Contraseña actualizada correctamente")
                .build();
    }

    /**
     * Obtiene el token de recuperación o lanza si es inválido o expirado.
     */
    private PasswordResetToken requireValidToken(String code) {
        PasswordResetToken token = tokenRepository.findByTokenAndUsedFalse(code)
                .orElseThrow(() -> new InvalidResetTokenException("Código inválido o expirado"));

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new InvalidResetTokenException("El código ha expirado");
        }
        return token;
    }

    /**
     * Genera un código aleatorio de 6 dígitos
     */
    private String generateSixDigitCode() {
        int code = random.nextInt(900000) + 100000; // 100000 - 999999
        return String.valueOf(code);
    }
}