package com.instagram.identity.service;

import org.springframework.stereotype.Service;
import java.time.Instant;
import java. util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service to manage blacklisted JWT tokens (logged out tokens).
 *
 * When a user logs out, their access token is added here.
 * Even if the token hasn't expired yet, it won't work anymore.
 *
 * Note: In production, use Redis instead of in-memory storage
 * so blacklist works across multiple server instances.
 */
@Service
public class TokenBlacklistService {

    // Store token + its expiry time
    // ConcurrentHashMap = thread-safe for multiple users logging out simultaneously
    private final Map<String, Instant> blacklistedTokens = new ConcurrentHashMap<>();

    /**
     * Add a token to the blacklist.
     * We store expiry time so we can clean up old tokens later.
     */
    public void blacklistToken(String token, Instant expiryTime) {
        blacklistedTokens.put(token, expiryTime);
    }

    /**
     * Check if a token is blacklisted (user logged out).
     */
    public boolean isBlacklisted(String token) {
        return blacklistedTokens.containsKey(token);
    }

    /**
     * Remove expired tokens from memory to prevent memory leaks.
     * This should be called periodically (e.g., every hour).
     *
     * In production:  Use Redis with TTL (Time To Live) instead.
     */
    public void cleanupExpiredTokens() {
        Instant now = Instant. now();
        blacklistedTokens.entrySet().removeIf(entry ->
                entry.getValue().isBefore(now)
        );
    }

    /**
     * Get count of blacklisted tokens (for monitoring/debugging).
     */
    public int getBlacklistSize() {
        return blacklistedTokens.size();
    }
}