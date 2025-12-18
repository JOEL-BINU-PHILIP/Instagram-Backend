package com.instagram.identity.controller.user;

import com.instagram.identity.model.User;
import com.instagram.identity.repository.UserRepository;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security. core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * ✅ IDENTITY SERVICE ONLY
 *
 * Responsibilities:
 *  - Return authenticated user account info
 *  - Check user permissions
 *  - Test authentication
 *
 * Does NOT handle:
 *  - Posts → Post Service
 *  - Profiles → Profile Service
 *  - Follows → Follow Service
 */
@RestController
@RequestMapping("/api/user")
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * ✅ KEEP - Get authenticated user's account info
     */
    @GetMapping("/me")
    public Map<String, Object> getCurrentUser(@AuthenticationPrincipal UserDetails userDetails) {

        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        Map<String, Object> account = new HashMap<>();
        account.put("id", user.getId());
        account.put("username", user.getUsername());
        account.put("fullName", user.getFullName());
        account.put("email", user.getEmail());
        account.put("accountType", user.getAccountType());
        account.put("verified", user.isVerified());
        account.put("privateAccount", user.isPrivateAccount());
        account.put("twoFactorEnabled", user.isTwoFactorEnabled());
        account.put("emailVerified", user.isEmailVerified());

        // Permission flags (used by other services)
        account.put("canPost", user.isCanPost());
        account.put("canComment", user.isCanComment());
        account.put("canMessage", user.isCanMessage());
        account.put("shadowBanned", user.isShadowBanned());
        account.put("suspended", user.isSuspended());

        return account;
    }

    /**
     * ✅ KEEP - Test authentication
     */
    @GetMapping("/test-auth")
    public Map<String, Object> testAuth(@AuthenticationPrincipal UserDetails userDetails) {
        Map<String, Object> response = new HashMap<>();

        if (userDetails == null) {
            response.put("authenticated", false);
            response.put("message", "No authentication found");
        } else {
            response.put("authenticated", true);
            response.put("username", userDetails.getUsername());
            response.put("authorities", userDetails.getAuthorities());
        }

        return response;
    }

    /**
     * ✅ NEW - Get user permissions
     *
     * Called by Post Service to check if user can post/comment.
     * This is the ONLY way other services should check permissions.
     */
    @GetMapping("/permissions")
    public Map<String, Object> getUserPermissions(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        Map<String, Object> permissions = new HashMap<>();
        permissions.put("userId", user.getId());
        permissions.put("username", user.getUsername());
        permissions.put("canPost", user.isCanPost());
        permissions.put("canComment", user.isCanComment());
        permissions.put("canMessage", user.isCanMessage());
        permissions.put("suspended", user.isSuspended());
        permissions.put("shadowBanned", user.isShadowBanned());

        return permissions;
    }
}