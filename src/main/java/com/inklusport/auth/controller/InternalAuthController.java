package com.inklusport.auth.controller;

import com.inklusport.auth.dto.LastLoginResponse;
import com.inklusport.auth.dto.LoginAttemptResponse;
import com.inklusport.auth.repository.AuthUserRepository;
import com.inklusport.auth.repository.LoginAttemptRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.List;

/**
 * Endpoints internos para que users-ms consulte accesos.
 */
@RestController
@RequestMapping("/api/internal/auth")
@RequiredArgsConstructor
public class InternalAuthController {

    private final AuthUserRepository authUserRepository;
    private final LoginAttemptRepository loginAttemptRepository;

    @PostMapping("/last-logins")
    public List<LastLoginResponse> lastLogins(@RequestBody(required = false) Collection<String> emails) {
        if (emails == null || emails.isEmpty()) {
            return List.of();
        }
        return authUserRepository.findByEmailIn(emails).stream()
                .map(user -> new LastLoginResponse(user.getEmail(), user.getLastLogin()))
                .toList();
    }

    @GetMapping("/last-login")
    public LastLoginResponse lastLogin(@RequestParam String email) {
        return authUserRepository.findByEmail(email)
                .map(user -> new LastLoginResponse(user.getEmail(), user.getLastLogin()))
                .orElse(new LastLoginResponse(email, null));
    }

    @GetMapping("/login-history")
    public List<LoginAttemptResponse> loginHistory(@RequestParam String email) {
        return loginAttemptRepository.findTop30ByEmailOrderByAttemptTimeDesc(email).stream()
                .map(attempt -> new LoginAttemptResponse(
                        attempt.getEmail(),
                        attempt.getSuccessful(),
                        attempt.getIpAddress(),
                        attempt.getAttemptTime()))
                .toList();
    }
}
