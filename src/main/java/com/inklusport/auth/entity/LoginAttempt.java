package com.inklusport.auth.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "login_attempt")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginAttempt {
    
  @Id
  @Column(name = "id", columnDefinition = "CHAR(36)")
  private String id = UUID.randomUUID().toString();
  
  @Column(name = "email", length = 100, nullable = false)
  private String email;
  
  @CreationTimestamp
  @Column(name = "attempt_time")
  private LocalDateTime attemptTime;
  
  @Column(name = "successful")
  private Boolean successful = false;
  
  @Column(name = "ip_address", length = 45)
  private String ipAddress;
}
