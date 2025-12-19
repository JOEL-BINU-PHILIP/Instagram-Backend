package com.instagram.post.model;

import lombok. Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org. springframework.data.mongodb.core. mapping.Document;

import java.time. Instant;
import java.util. ArrayList;
import java.util.List;

/**
 * ✅ INSTAGRAM-STYLE Post Model
 */
@Data
@Document(collection = "posts")
public class Post {

    @Id
    private String id;

    // ========================================
    // OWNER INFORMATION (Denormalized)
    // ========================================

    @Indexed
    private String userId;

    @Indexed
    private String username;

    private String userProfilePicture;

    // ========================================
    // POST CONTENT
    // ========================================

    private PostType type;

    private List<Media> mediaItems = new ArrayList<>();

    private String caption;

    private String altText;

    // ========================================
    // LOCATION
    // ========================================

    private Location location;

    // ========================================
    // TAGS & MENTIONS
    // ========================================

    @Indexed
    private List<String> taggedUserIds = new ArrayList<>();

    @Indexed
    private List<String> hashtags = new ArrayList<>();

    // ========================================
    // PRIVACY & PERMISSIONS
    // ========================================

    @Indexed
    private Visibility visibility = Visibility.PUBLIC;

    private boolean commentsDisabled = false;

    private boolean hideLikesCount = false;

    // ========================================
    // ENGAGEMENT COUNTERS (Denormalized)
    // ========================================

    private long likesCount = 0;

    private long commentsCount = 0;

    private long sharesCount = 0;

    private long savesCount = 0;

    private long viewsCount = 0;

    // ========================================
    // POST STATUS
    // ========================================

    @Indexed
    private boolean archived = false;

    @Indexed
    private boolean pinned = false;

    @Indexed
    private boolean deleted = false;

    private boolean edited = false;

    private Instant editedAt;

    // ========================================
    // TIMESTAMPS
    // ========================================

    @Indexed
    private Instant createdAt = Instant.now();

    private Instant updatedAt = Instant.now();

    private Instant deletedAt;

    // ========================================
    // HELPER METHODS
    // ========================================

    public boolean isOwner(String userId) {
        return this.userId.equals(userId);
    }

    public boolean isViewableBy(String viewerId, boolean isFollowing) {
        if (isOwner(viewerId)) {
            return true;
        }

        if (deleted) {
            return false;
        }

        if (visibility == Visibility.PUBLIC) {
            return true;
        }

        if (visibility == Visibility.PRIVATE) {
            return isFollowing;
        }

        return false;
    }

    public void incrementLikes() {
        this.likesCount++;
    }

    public void decrementLikes() {
        if (this.likesCount > 0) {
            this.likesCount--;
        }
    }

    public void incrementSaves() {
        this.savesCount++;
    }

    public void decrementSaves() {
        if (this.savesCount > 0) {
            this.savesCount--;
        }
    }
}