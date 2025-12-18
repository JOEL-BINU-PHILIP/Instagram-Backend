package com.instagram.identity.controller.user;

import com.instagram.identity.model.User;
import com.instagram.identity.repository.UserRepository;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security. core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * ✅ INSTAGRAM-STYLE User Controller
 *
 * Endpoints for authenticated users (NOT role-based).
 * Business logic enforced via flags, not roles.
 */
@RestController
@RequestMapping("/api/user")
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Get current user's profile.
     * Any authenticated user can access this.
     */
    @GetMapping("/me")
    public Map<String, Object> getCurrentUser(@AuthenticationPrincipal UserDetails userDetails) {

        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        Map<String, Object> profile = new HashMap<>();
        profile.put("id", user.getId());
        profile.put("username", user.getUsername());
        profile.put("fullName", user.getFullName());
        profile.put("email", user.getEmail());
        profile.put("bio", user.getBio());
        profile.put("profilePictureUrl", user.getProfilePictureUrl());
        profile.put("accountType", user.getAccountType());
        profile.put("verified", user.isVerified());
        profile.put("privateAccount", user.isPrivateAccount());
        profile.put("twoFactorEnabled", user.isTwoFactorEnabled());
        profile.put("emailVerified", user.isEmailVerified());

        return profile;
    }

    /**
     * Example: Create post endpoint.
     * ✅ FLAG-BASED authorization (not role-based).
     */
    @PostMapping("/posts")
    public Map<String, String> createPost(@AuthenticationPrincipal UserDetails userDetails,
                                          @RequestBody Map<String, String> postData) {

        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // ✅ INSTAGRAM-STYLE: Check flags, NOT roles
        if (! user.isCanPost()) {
            throw new RuntimeException("You cannot post at this time");
        }

        if (user.isShadowBanned()) {
            // Post accepted but marked as shadow banned
            // (actual implementation would mark in post service)
        }

        // ...  create post logic ...

        Map<String, String> response = new HashMap<>();
        response.put("message", "Post created successfully");
        return response;
    }

    /**
     * Example: Comment on post.
     * ✅ FLAG-BASED authorization.
     */
    @PostMapping("/posts/{postId}/comments")
    public Map<String, String> addComment(@AuthenticationPrincipal UserDetails userDetails,
                                          @PathVariable String postId,
                                          @RequestBody Map<String, String> commentData) {

        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // ✅ Check canComment flag
        if (!user.isCanComment()) {
            throw new RuntimeException("You cannot comment at this time");
        }

        // ... add comment logic ...

        Map<String, String> response = new HashMap<>();
        response.put("message", "Comment added");
        return response;
    }
}