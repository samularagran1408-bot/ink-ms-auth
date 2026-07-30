package com.inklusport.auth.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * Verifica localmente el ID token que emite Google Identity Services:
 * comprueba firma, emisor, caducidad y que el token fue emitido para
 * este cliente (audience). Nunca se confía en el token sin validar.
 */
@Service
@Slf4j
public class GoogleTokenVerifier {

  @Value("${google.client-id:}")
  private String clientId;

  private GoogleIdTokenVerifier verifier;

  /** Perfil mínimo que extraemos del token de Google. */
  public record GoogleProfile(String email, String name, String pictureUrl, boolean emailVerified) {}

  @PostConstruct
  void init() {
    if (!isEnabled()) {
      log.warn("google.client-id no configurado: el acceso con Google quedará deshabilitado.");
      return;
    }

    verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
        .setAudience(Collections.singletonList(clientId))
        .build();
  }

  public boolean isEnabled() {
    return clientId != null && !clientId.isBlank();
  }

  /**
   * @throws RuntimeException si el token es inválido o el proveedor no está configurado.
   */
  public GoogleProfile verify(String credential) {
    if (!isEnabled()) {
      throw new IllegalStateException("El acceso con Google no está habilitado en este servidor");
    }

    GoogleIdToken idToken;
    try {
      idToken = verifier.verify(credential);
    } catch (Exception e) {
      log.warn("No se pudo verificar el ID token de Google: {}", e.getMessage());
      throw new RuntimeException("No se pudo verificar el token de Google");
    }

    if (idToken == null) {
      throw new RuntimeException("Token de Google inválido o expirado");
    }

    GoogleIdToken.Payload payload = idToken.getPayload();
    boolean emailVerified = Boolean.TRUE.equals(payload.getEmailVerified());

    if (!emailVerified) {
      throw new RuntimeException("La cuenta de Google no tiene el correo verificado");
    }

    return new GoogleProfile(
        payload.getEmail(),
        (String) payload.get("name"),
        (String) payload.get("picture"),
        true);
  }
}
