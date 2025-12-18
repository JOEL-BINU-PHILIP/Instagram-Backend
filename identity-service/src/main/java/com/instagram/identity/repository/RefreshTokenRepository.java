package com.instagram.identity.repository;

import com.instagram.identity.model.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.time. Instant;
import java.util. List;
import java.util. Optional;

/**
 *Key changes from original:
 *  - findByToken() → findByTokenHash()
 *  - Added rotation tracking queries
 *  - Added security monitoring queries
 */
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {

    /**
     * Find token by SHA-256 hash (not plaintext).
     * This is the PRIMARY lookup method now.
     *
     * Used in:
     *  - rotateToken() - validate old token
     *  - verifyToken() - check token validity
     *  - revokeToken() - logout
     */
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Find all tokens for a specific user.
     *
     * Used for:
     *  - Security monitoring
     *  - Revoking all sessions on breach detection
     */
    List<RefreshToken> findByUserId(String userId);

    /**
     * Find all ACTIVE (non-revoked) tokens for a user.
     *
     * Useful for:
     *  - Limiting concurrent sessions
     *  - Showing user "active devices"
     */
    List<RefreshToken> findByUserIdAndRevokedFalse(String userId);

    /**
     *  REPLAY ATTACK DETECTION
     *
     * Find tokens that have already been used (usedAt is set).
     * If someone tries to reuse an old token, this catches it.
     *
     * Security flow:
     *  1. User refreshes token → usedAt is set
     *  2. Attacker tries to reuse old token
     *  3. This query finds it was already used
     *  4. System revokes ALL user sessions
     */
    Optional<RefreshToken> findByTokenHashAndUsedAtIsNotNull(String tokenHash);

    /**
     * Find tokens that were replaced (part of rotation chain).
     *
     * Used for:
     *  - Debugging rotation issues
     *  - Security audits
     */
    List<RefreshToken> findByReplacedByIsNotNull();

    /**
     *  Cleanup expired tokens (scheduled job).
     *
     * Find tokens that expired but weren't deleted yet.
     * Run this periodically to keep database clean.
     */
    List<RefreshToken> findByExpiresAtBefore(Instant timestamp);

    /**
     *  Count active sessions for a user.
     *
     * Security feature:
     *  - Limit to X active devices per user
     *  - Alert if unusual number of sessions
     */
    long countByUserIdAndRevokedFalse(String userId);

    /**
     * Find tokens by IP address (optional security feature).
     *
     * If you track IP addresses in RefreshToken model:
     *  - Detect login from new location
     *  - Alert user of suspicious activity
     */
    List<RefreshToken> findByIpAddress(String ipAddress);

    /**
     * Delete all revoked tokens older than X days.
     *
     * Database cleanup:
     *  - Keep recent revoked tokens for audit
     *  - Delete old ones to save space
     */
    void deleteByRevokedTrueAndExpiresAtBefore(Instant timestamp);
}