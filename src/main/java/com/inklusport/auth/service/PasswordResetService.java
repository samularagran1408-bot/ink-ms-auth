package com.inklusport.auth.service;

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

    @Transactional
    public ResetPasswordResponse resetPassword(ResetPasswordRequest request) {
        PasswordResetToken token = tokenRepository.findByTokenAndUsedFalse(request.getToken())
                .orElseThrow(() -> new RuntimeException("Código inválido o expirado"));

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("El código ha expirado");
        }

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
     * Genera un código aleatorio de 6 dígitos
     */
    private String generateSixDigitCode() {
        int code = random.nextInt(900000) + 100000; // 100000 - 999999
        return String.valueOf(code);
    }
}