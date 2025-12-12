package com.instagram.identity.repository;

import com.instagram.identity.model.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

/**
 * Repository for fetching roles from MongoDB.
 *
 * Example roles:
 *  - ROLE_ADMIN
 *  - ROLE_BUYER
 *  - ROLE_SELLER
 *
 * The method findByName automatically becomes:
 *   SELECT * FROM roles WHERE name = ?
 */
public interface RoleRepository extends MongoRepository<Role, String> {

    /**
     * Find a role by its name.
     * If it doesn't exist, user registration will fail.
     */
    Optional<Role> findByName(String name);
}
