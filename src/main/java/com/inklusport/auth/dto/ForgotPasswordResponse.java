package com.inklusport.auth.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ForgotPasswordResponse {
    private String message;
    /** Solo en desarrollo/Postman cuando expose-token-in-response está activo */
    private String resetToken;
}
