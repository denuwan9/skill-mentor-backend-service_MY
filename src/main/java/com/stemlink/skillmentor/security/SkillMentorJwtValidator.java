package com.stemlink.skillmentor.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.util.List;

@Slf4j
public class SkillMentorJwtValidator implements TokenValidator{

    private final String secretKey;

    public SkillMentorJwtValidator(String secretKey) {
        this.secretKey = secretKey;
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    @Override
    public String extractUserId(String token) {
        return extractUsername(token);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<String> extractRoles(String token) {
        return (List<String>) getClaims(token).get("roles", List.class);
    }

    @Override
    public String extractFirstName(String token) {
        return null;
    }

    @Override
    public String extractLastName(String token) {
        return null;
    }

    @Override
    public String extractEmail(String token) {
        return null;
    }

    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            log.error("Failed to validate JWT token: {}",e.getMessage());
            return false;
        }
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
