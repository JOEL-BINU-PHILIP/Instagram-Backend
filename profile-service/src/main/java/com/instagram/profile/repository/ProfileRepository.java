package com.instagram.profile.repository;

import com.instagram.profile.model.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

/**
 * Profile data access layer
 *
 * Indexed fields:
 *  - userId (unique)
 *  - username (unique)
 *
 * Both support fast lookups.
 */
public interface ProfileRepository extends MongoRepository<Profile, String> {

    /**
     * Find profile by userId (from JWT)
     */
    Optional<Profile> findByUserId(String userId);

    /**
     * Find profile by username (public URL)
     * Used for:  instagram.com/joel
     */
    Optional<Profile> findByUsername(String username);

    /**
     * Check if username exists
     * (NOT used for authentication - only for profile creation)
     */
    boolean existsByUsername(String username);
}