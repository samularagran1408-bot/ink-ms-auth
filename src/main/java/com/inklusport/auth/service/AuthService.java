package com.inklusport.auth.service;

import com.inklusport.auth.client.UserServiceClient;
import com.inklusport.auth.config.EmailAlreadyRegisteredException;
import com.inklusport.auth.dto.AuthResponse;
import com.inklusport.auth.dto.CompanionRequest;
import com.inklusport.auth.dto.CreateProfileFromRegisterRequest;
import com.inklusport.auth.dto.GoogleLoginRequest;
import com.inklusport.auth.dto.LoginRequest;
import com.inklusport.auth.dto.RegisterRequest;
import com.inklusport.auth.dto.UserProfileCreatedResponse;
import com.inklusport.auth.entity.AuthUser;
import com.inklusport.auth.entity.LoginAttempt;
import com.inklusport.auth.repository.AuthUserRepository;
import com.inklusport.auth.repository.LoginAttemptRepository;
import com.inklusport.auth.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;

/**
 * Servicio principal de autenticación.
 * Gestiona registro/login, trazabilidad de intentos y bloqueo temporal por fuerza bruta.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

  private final AuthUserRepository authUserRepository;
  private final LoginAttemptRepository loginAttemptRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtTokenProvider jwtTokenProvider;
  private final UserServiceClient userServiceClient;
  private final GoogleTokenVerifier googleTokenVerifier;

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  @Value("${security.rate-limit.max-attempts:5}")
  private int maxAttempts;

  @Value("${security.rate-limit.block-duration-minutes:15}")
  private int blockDurationMinutes;

  /**
   * Registra un usuario nuevo, materializa el perfil en users-ms
   * (incluyendo discapacidad / acompañante / preferencia de apoyo) y retorna token inicial.
   */
  @Transactional
  public AuthResponse register(RegisterRequest request, String ipAddress) {
    if (authUserRepository.existsByEmail(request.getEmail())) {
      throw new EmailAlreadyRegisteredException(request.getEmail());
    }

    AuthUser user = new AuthUser();
    user.setEmail(request.getEmail());
    user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
    user.setIsActive(true);

    authUserRepository.save(user);

    try {
      createUserProfileFromRegister(request);
    } catch (Exception ex) {
      // Compensa para no dejar credenciales huérfanas sin perfil.
      authUserRepository.delete(user);
      log.error("Fallo al crear perfil en users-ms para {}: {}", request.getEmail(), ex.getMessage());
      throw new RuntimeException(
              "No se pudo completar el registro: el perfil de usuario no pudo crearse. "
                      + "Verifique los datos de discapacidad e intente de nuevo.");
    }

    logLoginAttempt(request.getEmail(), ipAddress, true);

    String token = jwtTokenProvider.generateToken(user.getEmail(), List.of("USUARIO"));

    log.info("Nuevo usuario registrado: {}", user.getEmail());

    return AuthResponse.builder()
            .token(token)
            .tipo("Bearer")
            .id(null)
            .nombre(request.getNombre())
            .email(user.getEmail())
            .build();
  }

  private void createUserProfileFromRegister(RegisterRequest request) {
    CompanionRequest companion = request.getCompanion();

    CreateProfileFromRegisterRequest profileRequest = CreateProfileFromRegisterRequest.builder()
            .email(request.getEmail())
            .fullName(request.getNombre())
            .disability(blankToNull(request.getDisabilityType()))
            .companionFullName(companion != null ? blankToNull(companion.getFullName()) : null)
            .companionPhone(companion != null ? blankToNull(companion.getPhone()) : null)
            .companionRelationship(companion != null ? blankToNull(companion.getRelationship()) : null)
            .companionEmail(companion != null ? blankToNull(companion.getEmail()) : null)
            .build();

    UserProfileCreatedResponse profile = userServiceClient.createProfileFromRegister(profileRequest);
    if (profile == null || profile.getId() == null) {
      throw new IllegalStateException("Users MS no confirmó la creación del perfil");
    }
    log.info("Perfil creado en users-ms: {} (disability={})", profile.getEmail(), profile.getDisability());
  }

  private String blankToNull(String value) {
    return value == null || value.isBlank() ? null : value.trim();
  }

  /**
   * Valida credenciales, consulta roles en users-ms y genera JWT con claims de roles.
   */
  @Transactional
  public AuthResponse login(LoginRequest request, String ipAddress) {
      checkBruteForceBlock(request.getEmail(), ipAddress);

      // 1. Validar credenciales
      AuthUser user = authUserRepository.findByEmail(request.getEmail())
              .orElseThrow(() -> new RuntimeException("Credenciales inválidas"));

      if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
          logLoginAttempt(request.getEmail(), ipAddress, false);
          throw new RuntimeException("Credenciales inválidas");
      }

      if (!Boolean.TRUE.equals(user.getIsActive())) {
          throw new RuntimeException("Usuario inactivo");
      }

      logLoginAttempt(request.getEmail(), ipAddress, true);
      log.info("Usuario autenticado: {}", user.getEmail());

      // 2. Obtener roles (con fallback)
      List<String> roles = obtenerRolesConFallback(request.getEmail());

      // 3. Actualizar último login
      authUserRepository.updateLastLogin(request.getEmail(), LocalDateTime.now());

      // 4. Generar token CON roles
      String token = jwtTokenProvider.generateToken(user.getEmail(), roles);
      log.info("Token generado para {} con roles: {}", user.getEmail(), roles);
      log.info("Token: {}", token);

      return AuthResponse.builder()
              .token(token)
              .tipo("Bearer")
              .email(user.getEmail())
              .build();
  }

  /**
   * Autentica con Google: verifica el ID token, crea la cuenta la primera vez
   * y devuelve un JWT propio de InkluSport con los roles del usuario.
   */
  @Transactional
  public AuthResponse loginWithGoogle(GoogleLoginRequest request, String ipAddress) {
    GoogleTokenVerifier.GoogleProfile profile = googleTokenVerifier.verify(request.getCredential());
    String email = profile.email();

    AuthUser user = authUserRepository.findByEmail(email)
            .orElseGet(() -> createGoogleUser(email));

    if (!Boolean.TRUE.equals(user.getIsActive())) {
      throw new RuntimeException("Usuario inactivo");
    }

    logLoginAttempt(email, ipAddress, true);

    List<String> roles = obtenerRolesConFallback(email);
    authUserRepository.updateLastLogin(email, LocalDateTime.now());

    String token = jwtTokenProvider.generateToken(email, roles);
    log.info("Usuario autenticado con Google: {}", email);

    return AuthResponse.builder()
            .token(token)
            .tipo("Bearer")
            .nombre(profile.name())
            .email(email)
            .build();
  }

  /**
   * Alta implícita para cuentas de Google. Se genera una contraseña aleatoria
   * inutilizable: si el usuario quiere acceso con contraseña debe usar el flujo
   * de recuperación.
   */
  private AuthUser createGoogleUser(String email) {
    byte[] randomBytes = new byte[32];
    SECURE_RANDOM.nextBytes(randomBytes);

    AuthUser user = new AuthUser();
    user.setEmail(email);
    user.setPasswordHash(passwordEncoder.encode(Base64.getEncoder().encodeToString(randomBytes)));
    user.setIsActive(true);

    log.info("Cuenta creada desde Google para: {}", email);
    return authUserRepository.save(user);
  }

  /**
   * Obtiene roles del usuario con fallback seguro
   */
  private List<String> obtenerRolesConFallback(String email) {
      try {
          List<String> roles = userServiceClient.getUserRoles(email);
          if (roles != null && !roles.isEmpty()) {
              log.info("Roles obtenidos desde Users MS: {}", roles);
              return roles;
          }
          log.warn("Users MS devolvió roles vacíos para: {}", email);
      } catch (Exception e) {
          log.warn("Error conectando con Users MS: {}", e.getMessage());
      }
      
      log.info("Asignando rol USUARIO por defecto");
      return List.of("USUARIO");
  }

  /**
   * Guarda cada intento de login para auditoría y control de abuso.
   */
  private void logLoginAttempt(String email, String ipAddress, boolean successful) {
    LoginAttempt attempt = new LoginAttempt();
    attempt.setEmail(email);
    attempt.setIpAddress(ipAddress);
    attempt.setSuccessful(successful);

    loginAttemptRepository.save(attempt);

    if (!successful) {
      log.warn("Intento de login fallido - Email: {}, IP: {}", email, ipAddress);
    }
  }

  /**
   * Aplica bloqueo temporal si se superan los intentos fallidos permitidos.
   */
  private void checkBruteForceBlock(String email, String ipAddress) {
    LocalDateTime since = LocalDateTime.now().minusMinutes(blockDurationMinutes);

    long emailFailures = loginAttemptRepository.countRecentFailuresByEmail(email, since);
    long ipFailures = loginAttemptRepository.countRecentFailuresByIp(ipAddress, since);

    if (emailFailures >= maxAttempts) {
      throw new RuntimeException("Demasiados intentos fallidos. Cuenta temporalmente bloqueada por " + blockDurationMinutes + " minutos.");
    }

    if (ipFailures >= maxAttempts) {
      throw new RuntimeException("Demasiados intentos fallidos desde esta IP. Intente más tarde.");
    }
  }

  private List<String> getDefaultRoles() {
      return List.of("USUARIO");
  }
}
