package com.inklusport.auth.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Async
    public void sendPasswordResetCode(String to, String code, int expiryMinutes) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("Código de recuperación - InkluSport");
            helper.setText(buildEmailContent(code, expiryMinutes), true);

            mailSender.send(message);
            log.info("Código de recuperación enviado a: {}", to);
        } catch (MessagingException e) {
            log.error("Error al enviar código a {}: {}", to, e.getMessage());
        }
    }

    private String buildEmailContent(String code, int expiryMinutes) {
        return """
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body style="font-family: Arial, sans-serif;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #1E3A8A;">InkluSport</h2>
                    <h3>Recuperación de contraseña</h3>
                    <p>Recibimos una solicitud para restablecer tu contraseña.</p>
                    <p>Usa el siguiente código de verificación:</p>
                    <div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; letter-spacing: 10px; border-radius: 10px;">
                        <strong>%s</strong>
                    </div>
                    <p>Este código expirará en <strong>%d minutos</strong>.</p>
                    <p>Ingresa este código en la aplicación para restablecer tu contraseña.</p>
                    <p>Si no solicitaste este cambio, ignora este mensaje.</p>
                    <hr>
                    <p style="font-size: 12px; color: #666;">InkluSport - Deporte para todos</p>
                </div>
            </body>
            </html>
            """.formatted(code, expiryMinutes);
    }
}