package com.inklusport.auth.filter;

import com.inklusport.auth.security.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Filtro JWT para auth-ms.
 * Deja pasar rutas públicas y autentica el resto a partir del token Bearer.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtTokenProvider jwtTokenProvider;

  /**
   * Resuelve el usuario desde el token y lo inyecta en el SecurityContext.
   */
  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain)
          throws ServletException, IOException {

      String path = request.getRequestURI();

      if (path.equals("/api/auth/register") ||
          path.equals("/api/auth/login") ||
          path.equals("/api/auth/forgot-password") ||
          path.equals("/api/auth/reset-password") ||
          path.startsWith("/actuator")) {
          filterChain.doFilter(request, response);
          return;
      }

      String token = extractToken(request);

      if (token != null && jwtTokenProvider.validateToken(token)) {
          String email = jwtTokenProvider.getEmailFromToken(token);
          List<String> roles = jwtTokenProvider.getRolesFromToken(token);

        if (roles == null) {
            roles = List.of(); 
        }

    List<SimpleGrantedAuthority> authorities = roles.stream()
        .map(this::toAuthority)
        .collect(Collectors.toList());

          UsernamePasswordAuthenticationToken authentication =
                  new UsernamePasswordAuthenticationToken(email, null, authorities);

          SecurityContextHolder.getContext().setAuthentication(authentication);
          log.debug("Usuario autenticado: {}", email);
      }

      filterChain.doFilter(request, response);
  }

  private SimpleGrantedAuthority toAuthority(String role) {
    String normalized = role == null ? "" : role.trim().toUpperCase();
    if (normalized.startsWith("ROLE_")) {
      normalized = normalized.substring(5);
    }
    return new SimpleGrantedAuthority("ROLE_" + normalized);
  }

  private String extractToken(HttpServletRequest request) {
      String bearerToken = request.getHeader("Authorization");
      if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
          return bearerToken.substring(7);
      }
      return null;
  }
}
