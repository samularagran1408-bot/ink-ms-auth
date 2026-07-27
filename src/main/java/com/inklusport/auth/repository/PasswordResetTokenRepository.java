package com.inklusport.auth.repository;

import com.inklusport.auth.entity.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, String> {
    
  Optional<PasswordResetToken> findByTokenAndUsedFalse(String token);

  @Modifying
  @Transactional
  @Query("UPDATE PasswordResetToken t SET t.used = true WHERE t.token = :token")
  void markAsUsed(@Param("token") String token);
  
  @Modifying(clearAutomatically = true)
  @Transactional
  @Query("DELETE FROM PasswordResetToken t WHERE t.userId = :userId")
  void deleteByUserId(String userId);
}