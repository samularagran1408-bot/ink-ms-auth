package com.inklusport.auth.dto;

import com.inklusport.auth.validation.ValidDisabilityRegistration;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@ValidDisabilityRegistration
public class RegisterRequest {

  @NotBlank(message = "El nombre es obligatorio")
  @Size(min = 3, max = 100, message = "El nombre debe tener entre 3 y 100 caracteres")
  private String nombre;

  @NotBlank(message = "El email es obligatorio")
  @Email(message = "El email debe ser válido")
  private String email;

  @NotBlank(message = "La contraseña es obligatoria")
  @Size(min = 6, message = "La contraseña debe tener por lo menos 6 caracteres")
  private String password;

  /**
   * Tipo canónico: MOTRIZ, AUDITIVA, VISUAL, COGNITIVA, INTELECTUAL, MULTIPLE.
   * Opcional (null/blank = prefiero no indicar).
   */
  @Size(max = 50, message = "El tipo de discapacidad no puede superar 50 caracteres")
  private String disabilityType;

  /**
   * Obligatorio si disabilityType = MOTRIZ o AUDITIVA; opcional en el resto.
   */
  @Valid
  private CompanionRequest companion;
}
