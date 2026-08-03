package com.inklusport.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserAccessStatusResponse {
    private String email;
    private boolean allowed;
    private boolean active;
    private boolean permanentlyBlocked;
    private LocalDateTime blockedUntil;
    private String blockReason;
    private String message;
}
