package com.instagram.identity.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org. springframework.data.mongodb.core. mapping.Document;

import java.time. Instant;

/**
 * ✅ COMPLETE RefreshToken model with all rotation fields.
 */
@Data
@Document(collection = "refresh_tokens")
public class RefreshToken {

    @Id
    private String id;

    /**
     * ✅ Store SHA-256 hash of token (not plaintext).
     * Indexed for fast lookup.
     * Unique to prevent duplicates.
     */
    @Indexed(unique = true)
    private String tokenHash;

    /**
     * User who owns this token.
     * Indexed for fast "find all user tokens" queries.
     */
    @Indexed
    private String userId;

    /**
     * When token expires (14 days by default).
     */
    private Instant expiresAt;

    /**
     * When token was created.
     */
    private Instant createdAt = Instant.now();

    /**
     * If true, token cannot be used anymore.
     * Set during logout or security breach.
     */
    private boolean revoked = false;

    /**
     *   When token was used for refresh.
     * If NOT null → token was already used once.
     * Trying to reuse = replay attack.
     */
    private Instant usedAt;

    /**
     *  ID of the new token that replaced this one.
     * Creates audit trail of token rotation chain.
     */
    private String replacedBy;

    /**
     * IP address of client.
     * Detect login from unusual location.
     */
    @Indexed
    private String ipAddress;

    /**
     * Browser/device fingerprint.
     * Detect token theft across devices.
     */
    private String userAgent;
}