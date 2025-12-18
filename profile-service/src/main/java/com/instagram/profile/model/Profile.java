package com.instagram.profile.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org. springframework.data.mongodb.core.mapping.Document;

import java.time. Instant;

/**
 * INSTAGRAM-STYLE Profile Model
 *
 * Design principles:
 *  - IMMUTABLE:  userId, username (set once, never changed)
 *  - DENORMALIZED: follower/following/post counts (for performance)
 *  - MINIMAL: Only public-facing data
 *
 * This is NOT the User entity.
 * This is what OTHER users see when they view a profile.
 */
@Data
@Document(collection = "profiles")
public class Profile {

    @Id
    private String id;

    /**
     * IMMUTABLE: Set from JWT, never changed
     * Links to Identity Service's User. id
     */
    @Indexed(unique = true)
    private String userId;

    /**
     * IMMUTABLE: Set from JWT, never changed
     * Used for public profile URLs (instagram.com/joel)
     */
    @Indexed(unique = true)
    private String username;

    // ========================================
    // EDITABLE PROFILE DATA
    // ========================================

    private String fullName;

    private String bio;

    private String profilePictureUrl;

    /**
     * PRIVACY FLAG
     * If true:
     *  - Only approved followers see posts
     *  - Limited profile info shown to others
     */
    private boolean privateAccount = false;

    // ========================================
    // DENORMALIZED COUNTERS
    // ========================================

    /**
     * Updated by Follow Service via events
     */
    private long followersCount = 0;

    private long followingCount = 0;

    /**
     * Updated by Post Service via events
     */
    private long postsCount = 0;

    // ========================================
    // METADATA
    // ========================================

    private Instant createdAt = Instant.now();

    private Instant updatedAt = Instant.now();

    // ========================================
    // HELPER METHODS
    // ========================================

    /**
     * Check if profile should show limited info to viewer
     */
    public boolean isLimitedView(String viewerUserId) {
        // Owner always sees full profile
        if (this.userId.equals(viewerUserId)) {
            return false;
        }

        // Private accounts show limited view to non-followers
        return this.privateAccount;
    }
}