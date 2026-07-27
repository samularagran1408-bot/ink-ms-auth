package com.inklusport.auth.security;

import com.inklusport.auth.service.TokenRevocationService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {

  private final TokenRevocationService tokenRevocationService;

  /** Configuración de JWT */
  @Value("${jwt.secret}")
  private String jwtSecret;

  /** Expiración del JWT */
  @Value("${jwt.expiration}")
  private Long jwtExpiration;

  /** Clave secreta para firmar los tokens JWT */
  private Key key() {
      return Keys.hmacShaKeyFor(jwtSecret.getBytes());
  }

  /**
   * Genera un token JWT para el usuario autenticado
   * @param email
   * @param roles
   * @return
   */
  public String generateToken(String email) {
    return generateToken(email, List.of());
  }

  public String generateToken(String email, List<String> roles) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtExpiration);

    return Jwts.builder()
      .setSubject(email)
      .claim("roles", roles)
      .setIssuedAt(now)
      .setExpiration(expiryDate)
      .signWith(key(), SignatureAlgorithm.HS512)
      .compact();
  }

  /**
   * Obtiene el email del usuario a partir del token JWT
   * @param token
   * @return
   */
  public String getEmailFromToken(String token) {
    Claims claims = Jwts.parserBuilder()
      .setSigningKey(key())
      .build()
      .parseClaimsJws(token)
      .getBody();
    return claims.getSubject();
  }

  /**
   * Obtiene los roles del usuario a partir del token JWT
   * @param token
   * @return
   */
  @SuppressWarnings("unchecked")
  public List<String> getRolesFromToken(String token) {
    Claims claims = Jwts.parserBuilder()
      .setSigningKey(key())
      .build()
      .parseClaimsJws(token)
      .getBody();
    return claims.get("roles", List.class);
  }

  /**
   * Valida el token JWT
   * @param token
   * @return
   */
  public boolean validateToken(String token) {
    if (tokenRevocationService.isRevoked(token)) {
      log.warn("Intento de uso de token revocado");
      return false;
    }

    try {
      Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(token);
      return true;
    } catch (MalformedJwtException e) {
      log.error("Token JWT malformado: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      log.error("Token JWT expirado: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      log.error("Token JWT no soportado: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      log.error("Token JWT vacío: {}", e.getMessage());
    }
    return false;
  }
}
