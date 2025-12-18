package com.instagram.identity.service;

import com.instagram.identity.model.RefreshToken;
import com.instagram.identity.model.User;
import com.instagram.identity.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java. util.Base64;
import java.util. List;

/**
 * ✅ UPGRADED: Instagram-style refresh token rotation.
 *
 * Security improvements:
 *  1. Tokens stored as SHA-256 hashes (not plaintext)
 *  2. Automatic rotation on every use
 *  3. Replay attack detection
 *  4. Revoke all sessions on suspicious activity
 */
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final long validitySeconds;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            @Value("${jwt.refresh-token-validity-days}") long validityDays
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.validitySeconds = validityDays * 24 * 3600;
    }

    /**
     * Creates a new refresh token with IP tracking.
     *
     * @param user User requesting the token
     * @param ipAddress Client IP address (optional)
     * @param userAgent Browser fingerprint (optional)
     */
    public RefreshToken createToken(User user, String ipAddress, String userAgent) {
        String rawToken = generateSecureString();
        String tokenHash = hashToken(rawToken);

        RefreshToken token = new RefreshToken();
        token.setTokenHash(tokenHash);
        token.setUserId(user.getId());
        token.setExpiresAt(Instant.now().plusSeconds(validitySeconds));
        token.setRevoked(false);

        // ✅ Track security metadata
        token.setIpAddress(ipAddress);
        token.setUserAgent(userAgent);

        RefreshToken saved = refreshTokenRepository.save(token);

        // Return with raw token for cookie
        saved.setTokenHash(rawToken);
        return saved;
    }

    // Keep old method for backward compatibility
    public RefreshToken createToken(User user) {
        return createToken(user, null, null);
    }
    /**
     * ✅ INSTAGRAM-STYLE TOKEN ROTATION
     *
     * Flow:
     *  1. Validate old refresh token
     *  2. Check if already used (replay attack detection)
     *  3. Mark old token as used
     *  4. Create new refresh token
     *  5. Link tokens in rotation chain
     *
     * Security:
     *  - If token reused → revoke ALL user sessions
     *  - Prevents stolen token abuse
     */
    public RefreshToken rotateToken(String rawToken) {
        String tokenHash = hashToken(rawToken);

        // ✅ Find token by hash
        RefreshToken oldToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        // ✅ REPLAY ATTACK DETECTION
        if (oldToken.getUsedAt() != null) {
            // Token was already used once → SECURITY BREACH
            // Revoke ALL tokens for this user
            revokeAllUserTokens(oldToken.getUserId());
            throw new RuntimeException("Refresh token reuse detected - all sessions revoked");
        }

        // ✅ Check expiry
        if (oldToken.getExpiresAt().isBefore(Instant.now())) {
            throw new RuntimeException("Refresh token expired");
        }

        // ✅ Check if revoked
        if (oldToken. isRevoked()) {
            throw new RuntimeException("Refresh token has been revoked");
        }

        // ✅ Mark old token as USED
        oldToken.setUsedAt(Instant.now());

        // ✅ Create NEW refresh token
        String newRawToken = generateSecureString();
        String newTokenHash = hashToken(newRawToken);

        RefreshToken newToken = new RefreshToken();
        newToken.setTokenHash(newTokenHash);
        newToken.setUserId(oldToken.getUserId());
        newToken.setExpiresAt(Instant.now().plusSeconds(validitySeconds));
        newToken.setRevoked(false);

        RefreshToken savedNew = refreshTokenRepository.save(newToken);

        // ✅ Link tokens (rotation chain)
        oldToken.setReplacedBy(savedNew.getId());
        refreshTokenRepository.save(oldToken);

        // ✅ Return new token with RAW value (for cookie)
        savedNew.setTokenHash(newRawToken);
        return savedNew;
    }

    /**
     * Validates refresh token without rotation.
     * Used for read-only validation.
     */
    public RefreshToken verifyToken(String rawToken) {
        String tokenHash = hashToken(rawToken);

        return refreshTokenRepository.findByTokenHash(tokenHash)
                .filter(t -> !t.isRevoked())
                .filter(t -> t.getExpiresAt().isAfter(Instant.now()))
                .orElseThrow(() -> new RuntimeException("Invalid or expired refresh token"));
    }

    /**
     * Revoke a single refresh token.
     */
    public void revokeToken(String rawToken) {
        String tokenHash = hashToken(rawToken);

        refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
        });
    }

    /**
     * ✅ SECURITY:  Revoke ALL tokens for a user.
     * Used when replay attack detected.
     */
    public void revokeAllUserTokens(String userId) {
        List<RefreshToken> userTokens = refreshTokenRepository.findByUserId(userId);

        userTokens.forEach(token -> {
            token.setRevoked(true);
            token.setUsedAt(Instant.now());
        });

        refreshTokenRepository.saveAll(userTokens);
    }

    /**
     * Generate cryptographically secure random token.
     */
    private String generateSecureString() {
        byte[] bytes = new byte[64];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * ✅ Hash token using SHA-256.
     * Never store refresh tokens in plaintext.
     */
    private String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets. UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
    /**
     * ✅ CLEANUP: Delete old expired tokens.
     * Run this as a scheduled job (e.g., daily).
     *
     * Keeps database clean without growing forever.
     */
    public void cleanupExpiredTokens() {
        Instant cutoff = Instant.now().minus(30, java.time.temporal.ChronoUnit.DAYS);

        // Delete tokens that expired over 30 days ago
        refreshTokenRepository.deleteByRevokedTrueAndExpiresAtBefore(cutoff);
    }
    /**
     * ✅ SECURITY:  Limit concurrent sessions per user.
     *
     * Instagram allows ~5 active devices per account.
     * If exceeded, revoke oldest sessions.
     */
    public void enforceSessionLimit(String userId, int maxSessions) {
        List<RefreshToken> activeSessions = refreshTokenRepository
                .findByUserIdAndRevokedFalse(userId);

        if (activeSessions.size() > maxSessions) {
            // Sort by creation time, revoke oldest
            activeSessions. stream()
                    .sorted((a, b) -> a.getCreatedAt().compareTo(b.getCreatedAt()))
                    .limit(activeSessions.size() - maxSessions)
                    .forEach(token -> {
                        token.setRevoked(true);
                        refreshTokenRepository.save(token);
                    });
        }
    }
}