package com.inklusport.auth.controller;

import com.inklusport.auth.dto.AuthResponse;
import com.inklusport.auth.dto.ForgotPasswordRequest;
import com.inklusport.auth.dto.LoginRequest;
import com.inklusport.auth.dto.RegisterRequest;
import com.inklusport.auth.dto.ResetPasswordRequest;
import com.inklusport.common.dto.response.ErrorResponse;
import com.inklusport.auth.security.JwtTokenProvider;
import com.inklusport.auth.service.AuthService;
import com.inklusport.auth.service.PasswordResetService;
import com.inklusport.auth.service.TokenRevocationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Endpoints de autenticacion y gestion de tokens.
 * Flujo:
 * 1) Registro y login
 * 2) Recuperacion de contraseña
 * 3) Validacion de token JWT
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;
  private final PasswordResetService passwordResetService;
  private final JwtTokenProvider jwtTokenProvider;
  private final TokenRevocationService tokenRevocationService;

  
  /**
   * Registra un usuario nuevo y retorna los datos de autenticacion inicial.
   */
  @PostMapping("/register")
  public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
    try {
      AuthResponse response = authService.register(request, getClientIp(httpRequest));
      return ResponseEntity.ok(response);
    } catch (Exception e) {
      return buildErrorResponse(e, "/api/auth/register");
    }
  }

  /**
   * Autentica credenciales y devuelve la informacion de sesion/token.
   */
  @PostMapping("/login")
  public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
    try {
      AuthResponse response = authService.login(request, getClientIp(httpRequest));
      return ResponseEntity.ok(response);
    } catch (Exception e) {
      return buildErrorResponse(e, "/api/auth/login");
    }
  }

  /**
   * Endpoint de salida de sesion sin invalidacion persistente de token.
   */
  @PostMapping("/logout")
  public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return ResponseEntity.badRequest().body(Map.of("message", "Token no proporcionado"));
    }

    String token = authHeader.substring(7);
    tokenRevocationService.revokeToken(token);
    return ResponseEntity.ok(Map.of("message", "Logout exitoso"));
  }

  /**
   * Inicia el flujo de recuperacion de contraseña para un correo.
   */
  @PostMapping("/forgot-password")
  public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
      passwordResetService.forgotPassword(request);
      return ResponseEntity.ok(Map.of("message", "Si el email existe, recibirás instrucciones"));
  }

  /**
   * Aplica el cambio de contraseña usando el token de recuperacion.
   */
  @PostMapping("/reset-password")
  public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
      passwordResetService.resetPassword(request);
      return ResponseEntity.ok(Map.of("message", "Contraseña actualizada exitosamente"));
  }

  /**
   * Valida un JWT recibido en el header Authorization.
   */
  @GetMapping("/validate")
  public ResponseEntity<?> validateToken(@RequestHeader(value = "Authorization", required = false) String authHeader) {
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(Map.of("valid", false, "message", "Token no proporcionado o formato inválido"));
    }

    String token = authHeader.substring(7);

    if (jwtTokenProvider.validateToken(token)) {
      return ResponseEntity.ok(Map.of("valid", true, "email", jwtTokenProvider.getEmailFromToken(token)));
    }

    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .body(Map.of("valid", false, "message", "Token inválido o expirado"));
  }

  private String getClientIp(HttpServletRequest request) {
    String ip = request.getHeader("X-Forwarded-For");
    if (ip == null || ip.isEmpty()) {
      ip = request.getRemoteAddr();
    }
    return ip;
  }

  private ResponseEntity<ErrorResponse> buildErrorResponse(Exception e, String path) {
    ErrorResponse error = ErrorResponse.builder()
        .timestamp(LocalDateTime.now())
        .status(HttpStatus.BAD_REQUEST.value())
        .error("Bad Request")
        .message(e.getMessage())
        .path(path)
        .build();
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
  }
}
