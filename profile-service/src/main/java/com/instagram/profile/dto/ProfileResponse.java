package com. instagram.profile.dto;

import com.instagram.profile.model.Profile;

import java.time.Instant;

/**
 * INSTAGRAM-STYLE Profile Response
 *
 * Two modes:
 *  1. Full profile (owner or public account)
 *  2. Limited profile (private account, non-follower viewer)
 */
public record ProfileResponse(
        String username,
        String fullName,
        String bio,
        String profilePictureUrl,
        boolean privateAccount,
        Long followersCount,
        Long followingCount,
        Long postsCount,
        Instant createdAt
) {

    /**
     * Create full profile response
     */
    public static ProfileResponse fromProfile(Profile profile) {
        return new ProfileResponse(
                profile.getUsername(),
                profile.getFullName(),
                profile.getBio(),
                profile.getProfilePictureUrl(),
                profile.isPrivateAccount(),
                profile.getFollowersCount(),
                profile. getFollowingCount(),
                profile.getPostsCount(),
                profile.getCreatedAt()
        );
    }

    /**
     * Create limited profile response (private account)
     */
    public static ProfileResponse limitedView(Profile profile) {
        return new ProfileResponse(
                profile. getUsername(),
                profile.getFullName(),
                null, // Hide bio
                profile.getProfilePictureUrl(),
                true,
                null, // Hide counts
                null,
                null,
                null
        );
    }
}