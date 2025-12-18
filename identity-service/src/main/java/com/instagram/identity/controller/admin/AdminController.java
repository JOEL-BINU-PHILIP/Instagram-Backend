package com.instagram.identity.controller. admin;

import com.instagram. identity.model.User;
import com.instagram.identity.service.UserService;
import com. instagram.identity.repository.UserRepository;
import org. springframework.web.bind.annotation.*;

import java.time.Instant;
import java. time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

/**
 * ✅ INSTAGRAM-STYLE Admin Controller
 *
 * ONLY accessible by ROLE_ADMIN.
 * Used for user management, not business logic.
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;
    private final UserRepository userRepository;

    public AdminController(UserService userService, UserRepository userRepository) {
        this.userService = userService;
        this. userRepository = userRepository;
    }

    /**
     * Suspend a user.
     */
    @PostMapping("/users/{userId}/suspend")
    public Map<String, String> suspendUser(@PathVariable String userId,
                                           @RequestBody Map<String, String> request) {

        String reason = request.getOrDefault("reason", "Policy violation");
        Integer durationDays = request.get("durationDays") != null
                ? Integer.parseInt(request.get("durationDays"))
                : null;

        Instant expiresAt = durationDays != null
                ? Instant.now().plus(durationDays, ChronoUnit. DAYS)
                : null;

        userService.suspendUser(userId, reason, expiresAt);

        Map<String, String> response = new HashMap<>();
        response.put("message", "User suspended");
        response.put("reason", reason);
        return response;
    }

    /**
     * Unsuspend a user.
     */
    @PostMapping("/users/{userId}/unsuspend")
    public Map<String, String> unsuspendUser(@PathVariable String userId) {
        userService.unsuspendUser(userId);

        Map<String, String> response = new HashMap<>();
        response.put("message", "User unsuspended");
        return response;
    }

    /**
     * Restrict posting ability.
     */
    @PostMapping("/users/{userId}/restrict-posting")
    public Map<String, String> restrictPosting(@PathVariable String userId) {
        userService.updateContentPermissions(userId, false, true, true);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Posting restricted");
        return response;
    }

    /**
     * Get user details (admin view).
     */
    @GetMapping("/users/{userId}")
    public Map<String, Object> getUserDetails(@PathVariable String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Map<String, Object> details = new HashMap<>();
        details.put("id", user.getId());
        details.put("username", user.getUsername());
        details.put("email", user.getEmail());
        details.put("accountType", user.getAccountType());
        details.put("suspended", user.isSuspended());
        details.put("shadowBanned", user.isShadowBanned());
        details.put("canPost", user.isCanPost());
        details.put("canComment", user.isCanComment());
        details.put("verified", user.isVerified());
        details.put("lastLoginAt", user.getLastLoginAt());

        if (user.isSuspended()) {
            details.put("suspensionReason", user.getSuspensionReason());
            details.put("suspensionExpiresAt", user.getSuspensionExpiresAt());
        }

        return details;
    }
}