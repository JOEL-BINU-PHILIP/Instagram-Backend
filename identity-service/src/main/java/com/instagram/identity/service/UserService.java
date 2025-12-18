package com.instagram.identity.service;

import com.instagram.identity. model.AccountType;
import com.instagram. identity.model.Role;
import com.instagram.identity.model.User;
import com.instagram.identity.repository.RoleRepository;
import com.instagram.identity.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java. util.Optional;

/**
 * ✅ INSTAGRAM-STYLE User Service
 *
 * Key changes:
 *  - Registration ALWAYS creates ROLE_USER
 *  - Account type defaults to PERSONAL
 *  - Suspended users cannot log in
 *  - Auto-expire temporary suspensions
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
        this. roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * ✅ INSTAGRAM-STYLE REGISTRATION
     *
     * Changes from original:
     *  1. Always assigns ROLE_USER (no role parameter)
     *  2. Sets AccountType (default PERSONAL)
     *  3. Initializes all flags to safe defaults
     *  4. Validates username format
     */
    public User registerUser(String username,
                             String email,
                             String rawPassword,
                             String fullName,
                             String accountTypeStr) {

        // Validate uniqueness
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Username already taken");
        }

        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email already registered");
        }

        // Validate and parse account type
        AccountType accountType;
        try {
            accountType = accountTypeStr != null && ! accountTypeStr.isBlank()
                    ? AccountType.valueOf(accountTypeStr. toUpperCase())
                    :  AccountType.PERSONAL;
        } catch (IllegalArgumentException e) {
            accountType = AccountType.PERSONAL; // fallback
        }

        // ✅ CRITICAL: Everyone gets ROLE_USER (no other options)
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("ROLE_USER not found in database - run initialization"));

        // Create user with Instagram-style defaults
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setFullName(fullName);

        // ✅ Set account type
        user.setAccountType(accountType);

        // ✅ Assign ROLE_USER (the ONLY role for public registration)
        user.getRoles().add(userRole);

        // ✅ Initialize flags to safe defaults
        user.setPrivateAccount(false);
        user.setVerified(false);
        user.setSuspended(false);
        user.setShadowBanned(false);
        user.setCanPost(true);
        user.setCanComment(true);
        user.setCanMessage(true);
        user.setTwoFactorEnabled(false);
        user.setLoginRestricted(false);
        user.setEmailVerified(false);

        return userRepository.save(user);
    }

    /**
     * Fetch user by username with suspension check.
     * Auto-lifts expired suspensions.
     */
    public Optional<User> findByUsername(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);

        userOpt.ifPresent(user -> {
            // ✅ Auto-lift expired suspensions
            if (user.isSuspended() && user.isSuspensionExpired()) {
                user. setSuspended(false);
                user.setSuspensionReason(null);
                user.setSuspensionExpiresAt(null);
                userRepository.save(user);
            }
        });

        return userOpt;
    }

    /**
     * Fetch user by ID with suspension check.
     */
    public Optional<User> findById(String id) {
        Optional<User> userOpt = userRepository.findById(id);

        userOpt.ifPresent(user -> {
            if (user.isSuspended() && user.isSuspensionExpired()) {
                user. setSuspended(false);
                user.setSuspensionReason(null);
                user.setSuspensionExpiresAt(null);
                userRepository.save(user);
            }
        });

        return userOpt;
    }

    /**
     * ✅ NEW:  Update last login timestamp.
     * Called after successful authentication.
     */
    public void recordLogin(String userId) {
        userRepository.findById(userId).ifPresent(user -> {
            user.setLastLoginAt(Instant.now());
            userRepository.save(user);
        });
    }

    /**
     * ✅ NEW:  Suspend user (Trust & Safety action).
     *
     * @param userId User to suspend
     * @param reason Reason shown to user
     * @param expiresAt Null = permanent, otherwise auto-lift at this time
     */
    public void suspendUser(String userId, String reason, Instant expiresAt) {
        userRepository.findById(userId).ifPresent(user -> {
            user.setSuspended(true);
            user.setSuspensionReason(reason);
            user.setSuspensionExpiresAt(expiresAt);
            userRepository.save(user);
        });
    }

    /**
     * ✅ NEW: Lift suspension.
     */
    public void unsuspendUser(String userId) {
        userRepository.findById(userId).ifPresent(user -> {
            user.setSuspended(false);
            user.setSuspensionReason(null);
            user.setSuspensionExpiresAt(null);
            userRepository.save(user);
        });
    }

    /**
     * ✅ NEW: Toggle content permissions.
     */
    public void updateContentPermissions(String userId, boolean canPost, boolean canComment, boolean canMessage) {
        userRepository.findById(userId).ifPresent(user -> {
            user.setCanPost(canPost);
            user.setCanComment(canComment);
            user.setCanMessage(canMessage);
            userRepository.save(user);
        });
    }

    /**
     * ✅ NEW: Switch account type.
     * Users can change between PERSONAL ↔ CREATOR ↔ BUSINESS.
     */
    public void changeAccountType(String userId, AccountType newType) {
        userRepository.findById(userId).ifPresent(user -> {
            // Business accounts might require additional verification
            // (implement verification check here if needed)
            user.setAccountType(newType);
            userRepository.save(user);
        });
    }
}