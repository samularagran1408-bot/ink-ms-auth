package com.inklusport.auth.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenRevocationServiceTest {

    @Test
    void revokeToken_debeInvalidarElToken() {
        TokenRevocationService service = new TokenRevocationService();
        String token = "token-test";

        assertFalse(service.isRevoked(token));

        service.revokeToken(token);

        assertTrue(service.isRevoked(token));
    }
}
