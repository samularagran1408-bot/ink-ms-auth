package com.inklusport.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Datos del acompañante de apoyo. Obligatorio solo cuando el tipo de discapacidad
 * lo exige (MOTRIZ); opcional en el resto de casos.
 */
@Data
public class CompanionRequest {

    @NotBlank(message = "El nombre del acompañante es obligatorio")
    @Size(min = 3, max = 150, message = "El nombre del acompañante debe tener entre 3 y 150 caracteres")
    private String fullName;

    @NotBlank(message = "El teléfono del acompañante es obligatorio")
    @Size(min = 7, max = 20, message = "El teléfono del acompañante debe tener entre 7 y 20 caracteres")
    @Pattern(
            regexp = "^[+]?[0-9\\s()-]{7,20}$",
            message = "El teléfono del acompañante no tiene un formato válido"
    )
    private String phone;

    @Size(max = 80, message = "La relación con el acompañante no puede superar 80 caracteres")
    private String relationship;

    @Email(message = "El email del acompañante debe ser válido")
    @Size(max = 100, message = "El email del acompañante no puede superar 100 caracteres")
    private String email;
}
