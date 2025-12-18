package com.instagram. profile.service;

import com. instagram.profile.dto.ProfileResponse;
import com.instagram.profile.dto.UpdateProfileRequest;
import com.instagram.profile.model.Profile;
import com.instagram.profile.repository.ProfileRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;

/**
 * ✅ INSTAGRAM-STYLE Profile Service
 *
 * Responsibilities:
 *  - Auto-create profile on first access
 *  - Handle privacy logic
 *  - Update profile data
 *
 * Does NOT:
 *  - Authenticate users
 *  - Handle followers
 *  - Handle posts
 */
@Service
public class ProfileService {

    private final ProfileRepository profileRepository;

    public ProfileService(ProfileRepository profileRepository) {
        this.profileRepository = profileRepository;
    }

    /**
     * Get profile by username (public endpoint)
     *
     * Privacy rules:
     *  - Public profile → full response
     *  - Private profile → limited response
     */
    public ProfileResponse getProfileByUsername(String username, String viewerUserId) {
        Profile profile = profileRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Profile not found"));

        // INSTAGRAM-STYLE:  Show limited view for private accounts
        if (profile.isLimitedView(viewerUserId)) {
            return ProfileResponse. limitedView(profile);
        }

        return ProfileResponse.fromProfile(profile);
    }

    /**
     * Get own profile (authenticated endpoint)
     *
     * Auto-creates profile if missing.
     */
    public ProfileResponse getMyProfile(String userId, String username) {
        Profile profile = profileRepository.findByUserId(userId)
                .orElseGet(() -> createProfile(userId, username));

        return ProfileResponse.fromProfile(profile);
    }

    /**
     * Update own profile
     *
     * Only owner can update.
     */
    public ProfileResponse updateMyProfile(String userId, UpdateProfileRequest request) {
        Profile profile = profileRepository. findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Profile not found"));

        // Update only non-null fields
        if (request.fullName() != null) {
            profile. setFullName(request.fullName());
        }

        if (request.bio() != null) {
            profile.setBio(request.bio());
        }

        if (request.profilePictureUrl() != null) {
            profile.setProfilePictureUrl(request.profilePictureUrl());
        }

        if (request.privateAccount() != null) {
            profile.setPrivateAccount(request.privateAccount());
        }

        profile.setUpdatedAt(Instant.now());

        Profile updated = profileRepository.save(profile);
        return ProfileResponse.fromProfile(updated);
    }

    /**
     * LAZY PROFILE CREATION
     *
     * Called when user logs in for first time.
     * userId and username extracted from JWT.
     */
    private Profile createProfile(String userId, String username) {
        Profile profile = new Profile();
        profile.setUserId(userId);
        profile.setUsername(username);
        profile.setFullName(username); // Default to username
        profile.setPrivateAccount(false);
        profile.setFollowersCount(0L);
        profile.setFollowingCount(0L);
        profile.setPostsCount(0L);

        return profileRepository.save(profile);
    }
}