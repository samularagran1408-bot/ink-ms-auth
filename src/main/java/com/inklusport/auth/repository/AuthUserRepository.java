package com.inklusport.auth.repository;

import com.inklusport.auth.entity.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

public interface AuthUserRepository extends JpaRepository<AuthUser, String> {
    
  Optional<AuthUser> findByEmail(String email);
  
  boolean existsByEmail(String email);
  
  @Modifying
  @Transactional
  @Query("UPDATE AuthUser u SET u.lastLogin = :lastLogin WHERE u.email = :email")
  void updateLastLogin(@Param("email") String email, @Param("lastLogin") LocalDateTime lastLogin);
}