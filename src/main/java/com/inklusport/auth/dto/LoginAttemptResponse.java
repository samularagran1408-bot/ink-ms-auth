package com.inklusport.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginAttemptResponse {
    private String email;
    private Boolean successful;
    private String ipAddress;
    private LocalDateTime attemptTime;
}
