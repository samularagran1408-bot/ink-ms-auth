package com.inklusport.auth.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "auth_user")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthUser {
    
  @Id
  @Column(name = "id", columnDefinition = "CHAR(36)")
  private String id = UUID.randomUUID().toString();
  
  @Column(name = "email", length = 100, unique = true, nullable = false)
  private String email;
  
  @Column(name = "password_hash", length = 255, nullable = false)
  private String passwordHash;
  
  @Column(name = "is_active")
  private Boolean isActive = true;
  
  @Column(name = "last_login")
  private LocalDateTime lastLogin;
  
  @CreationTimestamp
  @Column(name = "created_at")
  private LocalDateTime createdAt;
}
