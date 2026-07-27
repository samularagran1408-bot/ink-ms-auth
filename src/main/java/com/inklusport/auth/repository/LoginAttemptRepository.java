package com.inklusport.auth.repository;

import com.inklusport.auth.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, String> {
    
    @Query("SELECT COUNT(l) FROM LoginAttempt l WHERE l.email = :email AND l.successful = false AND l.attemptTime > :since")
    long countRecentFailuresByEmail(@Param("email") String email, @Param("since") LocalDateTime since);
    
    @Query("SELECT COUNT(l) FROM LoginAttempt l WHERE l.ipAddress = :ip AND l.successful = false AND l.attemptTime > :since")
    long countRecentFailuresByIp(@Param("ip") String ip, @Param("since") LocalDateTime since);
}