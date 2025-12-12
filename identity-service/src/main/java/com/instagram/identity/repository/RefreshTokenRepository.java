package com.instagram.identity.repository;

import com.instagram.identity.model.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

/**
 * This repository interacts with the "refresh_tokens" collection in MongoDB.
 *
 * MongoRepository gives built-in methods like:
 *  - save()
 *  - findAll()
 *  - delete()
 *  - findById()
 *
 * We add custom query methods by simply naming them properly.
 */
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {

    /**
     * Finds a refresh token by the actual token string.
     * Example: SELECT * FROM refresh_tokens WHERE token = ?
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Returns all valid (non-revoked) refresh tokens for a given user.
     * Useful if you want to allow only one active refresh token per user.
     */
    List<RefreshToken> findByUserIdAndRevokedFalse(String userId);
}
