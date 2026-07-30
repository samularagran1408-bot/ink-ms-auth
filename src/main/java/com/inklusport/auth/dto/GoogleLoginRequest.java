package com.inklusport.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * ID token (JWT) emitido por Google Identity Services en el navegador.
 */
@Data
public class GoogleLoginRequest {

  @NotBlank(message = "El credential de Google es obligatorio")
  private String credential;
}
