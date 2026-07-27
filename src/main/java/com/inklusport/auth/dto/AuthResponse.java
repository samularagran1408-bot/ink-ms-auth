package com.inklusport.auth.dto;

import lombok.Builder;
import lombok.Data;


@Data
@Builder
public class AuthResponse {
    private String token;
    private String tipo;
    private Long id;
    private String nombre;
    private String email;
}
