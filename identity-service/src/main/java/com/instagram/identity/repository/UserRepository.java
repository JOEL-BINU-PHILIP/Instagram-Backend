package com.instagram.identity.repository;

import com.instagram.identity.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

/**
 * Repository used to load user data from "users" collection in MongoDB.
 *
 * Spring Security depends on this to:
 *  - fetch user details
 *  - check username/email uniqueness
 */
public interface UserRepository extends MongoRepository<User, String> {

    /**
     * Lookup a user by username (used during login).
     */
    Optional<User> findByUsername(String username);

    /**
     * Check if a username already exists.
     * Useful during registration validation.
     */
    boolean existsByUsername(String username);

    /**
     * Prevent duplicate email registrations.
     */
    boolean existsByEmail(String email);
}
