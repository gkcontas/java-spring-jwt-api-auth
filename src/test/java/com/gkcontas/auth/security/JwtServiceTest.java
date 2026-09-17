package com.gkcontas.auth.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.gkcontas.auth.model.Role;
import com.gkcontas.auth.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class JwtServiceTest {

    private static final String SECRET = "test-secret-value-that-is-long-enough-for-hs512-signing-1234567890";

    private final JwtService jwtService = new JwtService(SECRET, Duration.ofMinutes(15), Duration.ofDays(7));

    private User sampleUser() {
        User user = new User("alice@example.com", "irrelevant-hash");
        user.addRole(new Role(Role.USER));
        return user;
    }

    @Test
    void shouldGenerateAccessTokenWithEmailAndRolesClaims() {
        String token = jwtService.generateAccessToken(sampleUser());

        Claims claims = jwtService.parse(token).getPayload();

        assertThat(claims.getSubject()).isEqualTo("alice@example.com");
        assertThat(claims.get(JwtService.TOKEN_TYPE_CLAIM, String.class)).isEqualTo(JwtService.ACCESS_TOKEN_TYPE);
        @SuppressWarnings("unchecked")
        List<String> roles = claims.get(JwtService.ROLES_CLAIM, List.class);
        assertThat(roles).contains(Role.USER);
    }

    @Test
    void shouldGenerateRefreshTokenMarkedWithRefreshType() {
        String token = jwtService.generateRefreshToken(sampleUser());

        Claims claims = jwtService.parse(token).getPayload();

        assertThat(claims.get(JwtService.TOKEN_TYPE_CLAIM, String.class)).isEqualTo(JwtService.REFRESH_TOKEN_TYPE);
    }

    @Test
    void shouldRejectAnExpiredToken() throws InterruptedException {
        JwtService shortLivedJwtService = new JwtService(SECRET, Duration.ofMillis(1), Duration.ofMillis(1));
        String token = shortLivedJwtService.generateAccessToken(sampleUser());

        Thread.sleep(10);

        assertThatThrownBy(() -> shortLivedJwtService.parse(token))
                .isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    void shouldRejectATokenSignedWithADifferentSecret() {
        JwtService otherJwtService = new JwtService(
                "a-completely-different-secret-value-also-long-enough-for-hs512",
                Duration.ofMinutes(15), Duration.ofDays(7));
        String token = otherJwtService.generateAccessToken(sampleUser());

        assertThatThrownBy(() -> jwtService.parse(token))
                .isInstanceOf(SignatureException.class);
    }
}
