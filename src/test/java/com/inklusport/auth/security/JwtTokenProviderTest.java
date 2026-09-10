package com.inklusport.auth.security;

import com.inklusport.auth.service.TokenRevocationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtTokenProviderTest {

    private static final String SECRET =
            "inklusport2024superSecretKeyForJWTtokenGenerationWith512bitsAlgorithmHS512";

    private TokenRevocationService tokenRevocationService;
    private JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setUp() {
        tokenRevocationService = new TokenRevocationService();
        jwtTokenProvider = new JwtTokenProvider(tokenRevocationService);
        ReflectionTestUtils.setField(jwtTokenProvider, "jwtSecret", SECRET);
        ReflectionTestUtils.setField(jwtTokenProvider, "jwtExpiration", 3_600_000L);
    }

    @Test
    void generateToken_incluyeEmailYRoles() {
        String token = jwtTokenProvider.generateToken("atleta@inklusport.test", List.of("USUARIO", "ENTRENADOR"));

        assertEquals("atleta@inklusport.test", jwtTokenProvider.getEmailFromToken(token));
        assertEquals(List.of("USUARIO", "ENTRENADOR"), jwtTokenProvider.getRolesFromToken(token));
        assertTrue(jwtTokenProvider.validateToken(token));
    }

    @Test
    void validateToken_rechazaTokenRevocadoOInvalido() {
        String token = jwtTokenProvider.generateToken("atleta@inklusport.test", List.of("USUARIO"));
        tokenRevocationService.revokeToken(token);

        assertFalse(jwtTokenProvider.validateToken(token));
        assertFalse(jwtTokenProvider.validateToken("no-es-un-jwt"));
    }
}
