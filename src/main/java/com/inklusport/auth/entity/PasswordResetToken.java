package com.inklusport.auth.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "password_reset_token")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetToken {
    
  @Id
  @Column(name = "id", columnDefinition = "CHAR(36)")
  private String id = UUID.randomUUID().toString();
  
  @Column(name = "user_id", columnDefinition = "CHAR(36)", nullable = false)
  private String userId;
  
  @Column(name = "token", unique = true, nullable = false, length = 6)
  private String token;
  
  @Column(name = "expires_at", nullable = false)
  private LocalDateTime expiresAt;
  
  @Column(name = "used")
  private Boolean used = false;
}
