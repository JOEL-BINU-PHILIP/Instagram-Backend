package com.instagram.identity.service;

import com.instagram.identity.model.Role;
import com.instagram.identity.model.User;
import com.instagram.identity.repository.RoleRepository;
import com.instagram.identity.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Handles user-related operations such as:
 *  - Registering new users
 *  - Validating uniqueness of username/email
 *  - Fetching users for authentication
 */
@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder) {

        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Creates a new user and saves to MongoDB.
     *
     * Steps:
     *  1. Check if username already exists
     *  2. Check if email already exists
     *  3. Validate role
     *  4. Create user object
     *  5. Hash password using BCrypt
     */
    public User registerUser(String username, String email, String rawPassword, String roleName) {

        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Username already exists");
        }

        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email already exists");
        }

        // Find the role from DB
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Invalid role: " + roleName));

        // Create new user object
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);

        // Store encrypted password (never plaintext)
        user.setPasswordHash(passwordEncoder.encode(rawPassword));

        // Assign role to the user
        user.getRoles().add(role);

        userRepository.save(user);
        return user;
    }

    /**
     * Fetch user by username (used during login).
     */
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Fetch user by ID (used when refreshing access token).
     */
    public Optional<User> findById(String id) {
        return userRepository.findById(id);
    }
}
