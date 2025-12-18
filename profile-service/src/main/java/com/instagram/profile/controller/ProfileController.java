package com.instagram.profile.controller;

import com.instagram.profile. dto.ProfileResponse;
import com. instagram.profile.dto.UpdateProfileRequest;
import com.instagram.profile.service.ProfileService;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security. core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

/**
 * ✅ FIXED: Extract username properly from UserDetails
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
     */
    @GetMapping("/{username}")
    public ProfileResponse getProfile(
            @PathVariable("username") String username,
            Authentication authentication) {  // ✅ Use Authentication instead

        String viewerId = null;
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof UserDetails) {
                viewerId = ((UserDetails) principal).getUsername();
            } else if (principal instanceof String) {
                viewerId = (String) principal;
            }
        }

        return profileService.getProfileByUsername(username, viewerId);
    }

    /**
     * AUTHENTICATED ENDPOINT: Get own profile
     *
     * ✅ FIXED: Extract username from UserDetails
     */
    @GetMapping("/me")
    public ProfileResponse getMyProfile(@AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        return profileService.getMyProfile(username, username);
    }

    /**
     * AUTHENTICATED ENDPOINT: Update own profile
     *
     * ✅ FIXED: Extract username from UserDetails
     */
    @PutMapping("/me")
    public ProfileResponse updateMyProfile(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody UpdateProfileRequest request) {

        String username = userDetails.getUsername();
        return profileService. updateMyProfile(username, request);
    }
}