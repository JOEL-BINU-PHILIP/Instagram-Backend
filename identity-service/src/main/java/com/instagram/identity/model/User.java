package com.instagram.identity.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework. data.mongodb.core.mapping. Document;

import java.time. Instant;
import java.util.HashSet;
import java.util. Set;

/**
 * ✅ INSTAGRAM-STYLE User Model
 *
 * ⚠️ IMPORTANT: Using @Getter/@Setter instead of @Data for boolean fields
 * to ensure proper getter method names (canPost() instead of isCanPost())
 */
@Getter
@Setter
@Document(collection = "users")
public class User {

    @Id
    private String id;

    @Indexed(unique = true)
    private String username;

    @Indexed(unique = true)
    private String email;

    private String passwordHash;

    private Instant createdAt = Instant.now();

    // ========================================
    // ROLES
    // ========================================

    @DBRef
    private Set<Role> roles = new HashSet<>();

    // ========================================
    // ACCOUNT TYPE
    // ========================================

    private AccountType accountType = AccountType.PERSONAL;

    // ========================================
    // INSTAGRAM-STYLE FLAGS
    // ========================================

    // Privacy & Visibility
    private boolean privateAccount = false;
    private boolean verified = false;

    // Trust & Safety
    private boolean suspended = false;
    private boolean shadowBanned = false;

    // Content Permissions
    // ✅ These will generate canPost(), canComment(), canMessage()
    private boolean canPost = true;
    private boolean canComment = true;
    private boolean canMessage = true;

    // Security & Authentication
    private boolean twoFactorEnabled = false;
    private boolean loginRestricted = false;
    private boolean emailVerified = false;

    // Additional Metadata
    private String fullName;
    private String bio;
    private String profilePictureUrl;
    private Instant lastLoginAt;
    private String suspensionReason;
    private Instant suspensionExpiresAt;

    // ========================================
    // HELPER METHODS
    // ========================================

    /**
     * Check if user can authenticate.
     */
    public boolean canAuthenticate() {
        return !suspended && !loginRestricted;
    }

    /**
     * Check if user is active.
     */
    public boolean isActive() {
        return !suspended;
    }

    /**
     * Check if user is internal staff.
     */
    public boolean isStaff() {
        return roles.stream()
                .anyMatch(role -> role.getName().equals("ROLE_ADMIN") ||
                        role.getName().equals("ROLE_MODERATOR"));
    }

    /**
     * Check if user has verified badge.
     */
    public boolean hasVerifiedBadge() {
        return verified;
    }

    /**
     * Check if suspension has expired.
     */
    public boolean isSuspensionExpired() {
        if (! suspended) return false;
        if (suspensionExpiresAt == null) return false;
        return Instant.now().isAfter(suspensionExpiresAt);
    }
}