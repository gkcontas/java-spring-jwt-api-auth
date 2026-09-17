package com.gkcontas.auth.security;

import com.gkcontas.auth.model.Role;
import com.gkcontas.auth.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Issues and validates the two token types used by this API: short-lived
 * "access" tokens (sent as {@code Authorization: Bearer <token>} on every
 * protected request) and longer-lived "refresh" tokens (only ever sent to
 * {@code POST /auth/refresh} to mint a new access token).
 */
@Component
public class JwtService {

    public static final String TOKEN_TYPE_CLAIM = "type";
    public static final String ROLES_CLAIM = "roles";
    public static final String ACCESS_TOKEN_TYPE = "access";
    public static final String REFRESH_TOKEN_TYPE = "refresh";

    private final SecretKey key;
    private final Duration accessTokenTtl;
    private final Duration refreshTokenTtl;

    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.access-token-ttl}") Duration accessTokenTtl,
            @Value("${app.jwt.refresh-token-ttl}") Duration refreshTokenTtl
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenTtl = accessTokenTtl;
        this.refreshTokenTtl = refreshTokenTtl;
    }

    public String generateAccessToken(User user) {
        return buildToken(user, accessTokenTtl, ACCESS_TOKEN_TYPE);
    }

    public String generateRefreshToken(User user) {
        return buildToken(user, refreshTokenTtl, REFRESH_TOKEN_TYPE);
    }

    /**
     * Parses and verifies the token signature/expiration. Throws
     * {@link JwtException} for anything invalid (bad signature, malformed,
     * expired) — callers decide how to translate that into an HTTP response.
     */
    public Jws<Claims> parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token);
    }

    private String buildToken(User user, Duration ttl, String tokenType) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(user.getEmail())
                .claim(ROLES_CLAIM, user.getRoles().stream().map(Role::getName).toList())
                .claim(TOKEN_TYPE_CLAIM, tokenType)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl)))
                .signWith(key)
                .compact();
    }
}
