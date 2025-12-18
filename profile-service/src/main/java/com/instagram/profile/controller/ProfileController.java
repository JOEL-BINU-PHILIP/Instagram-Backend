package com.instagram.profile.controller;

import com.instagram.profile.dto.ProfileResponse;
import com.instagram. profile.dto.UpdateProfileRequest;
import com.instagram.profile. service.ProfileService;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * INSTAGRAM-STYLE Profile Controller
 *
 * Endpoints:
 *  GET  /profiles/{username}  - Public (with privacy)
 *  GET  /profiles/me          - Authenticated (owner)
 *  PUT  /profiles/me          - Authenticated (owner)
 */
@RestController
@RequestMapping("/profiles")
@CrossOrigin(origins = "${cors.allowed-origins: http://localhost:3000}", allowCredentials = "true")
public class ProfileController {

    private final ProfileService profileService;

    public ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    /**
     * PUBLIC ENDPOINT:  View any user's profile
     *
     * Behavior:
     *  - Public account → full profile
     *  - Private account → limited info
     *
     * Does NOT throw 403 for private profiles.
     */
    @GetMapping("/{username}")
    public ProfileResponse getProfile(
            @PathVariable String username,
            @AuthenticationPrincipal String viewerUsername) {

        // viewerUsername is null if not authenticated
        String viewerId = viewerUsername != null ? viewerUsername : null;

        return profileService.getProfileByUsername(username, viewerId);
    }

    /**
     * AUTHENTICATED ENDPOINT: Get own profile
     *
     * Auto-creates profile if missing.
     */
    @GetMapping("/me")
    public ProfileResponse getMyProfile(@AuthenticationPrincipal String username) {
        // In real implementation, extract userId from JWT claims
        // For now, using username as userId (Identity Service does this)
        return profileService. getMyProfile(username, username);
    }

    /**
     * AUTHENTICATED ENDPOINT: Update own profile
     *
     * Allowed updates:
     *  - fullName
     *  - bio
     *  - profilePictureUrl
     *  - privateAccount
     */
    @PutMapping("/me")
    public ProfileResponse updateMyProfile(
            @AuthenticationPrincipal String username,
            @Valid @RequestBody UpdateProfileRequest request) {

        return profileService.updateMyProfile(username, request);
    }
}