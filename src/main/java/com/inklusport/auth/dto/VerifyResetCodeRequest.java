package com.inklusport.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class VerifyResetCodeRequest {

  @NotBlank(message = "El código es obligatorio")
  @Size(min = 6, max = 6, message = "El código debe tener 6 dígitos")
  private String token;
}
