package com.instagram.identity.service;

import com.instagram.identity.model.RefreshToken;
import com.instagram.identity.model.User;
import com.instagram.identity.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

/**
 * Handles everything related to refresh tokens.
 *
 * Responsibilities:
 *  - Create new refresh tokens
 *  - Validate tokens when users request new access tokens
 *  - Revoke tokens during logout
 *
 * Refresh tokens are stored in MongoDB so they can be revoked.
 */
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    // Expiry time for refresh tokens (converted from days → seconds)
    private final long validitySeconds;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            @Value("${jwt.refresh-token-validity-days}") long validityDays
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.validitySeconds = validityDays * 24 * 3600; // convert days into seconds
    }

    /**
     * Creates and saves a new refresh token for the given user.
     * Called during login.
     */
    public RefreshToken createToken(User user) {
        RefreshToken token = new RefreshToken();

        token.setToken(generateSecureString());               // random secure token
        token.setUserId(user.getId());                       // link token → user
        token.setExpiresAt(Instant.now().plusSeconds(validitySeconds));
        token.setRevoked(false);                             // token is active

        refreshTokenRepository.save(token);
        return token;
    }

    /**
     * Validates the refresh token:
     *  1. Must exist in DB
     *  2. Must NOT be revoked
     *  3. Must NOT be expired
     *
     * If any condition fails → throw exception.
     */
    public RefreshToken verifyToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .filter(t -> !t.isRevoked())                        // not revoked
                .filter(t -> t.getExpiresAt().isAfter(Instant.now())) // not expired
                .orElseThrow(() -> new RuntimeException("Invalid or expired refresh token"));
    }

    /**
     * Marks a refresh token as revoked. Used on logout.
     */
    public void revokeToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(t -> {
            t.setRevoked(true);
            refreshTokenRepository.save(t);
        });
    }

    /**
     * Generates a long, secure random string for refresh tokens.
     * Uses SecureRandom → cryptographically safe.
     */
    private String generateSecureString() {
        byte[] bytes = new byte[64];         // 64 bytes → strong token
        new SecureRandom().nextBytes(bytes); // random bytes
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
