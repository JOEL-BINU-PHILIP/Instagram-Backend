package com.instagram.identity.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

/**
 * Represents a refresh token stored in MongoDB.
 *
 * Why do we store refresh tokens?
 *  - Access tokens (JWT) expire quickly (15 mins)
 *  - Refresh tokens are long-lived (days)
 *  - We must track which refresh tokens are valid or revoked
 *
 * Fields:
 *  - token: the actual long secure string
 *  - userId: owner of the token
 *  - expiresAt: when token becomes invalid
 *  - revoked: true means user logged out / token blacklisted
 */
@Data
@Document(collection = "refresh_tokens")
public class RefreshToken {

    @Id
    private String id; // MongoDB unique ID for this token entry

    private String token;   // secure random string used as refresh token
    private String userId;  // ID of the user this token belongs to

    private Instant expiresAt;      // token expiry time
    private Instant createdAt = Instant.now(); // automatically set at creation

    private boolean revoked = false; // if true → token cannot be used anymore
}
