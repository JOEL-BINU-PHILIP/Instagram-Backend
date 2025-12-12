package com.instagram.identity.controller.admin;

import com.instagram.identity.scheduler.TokenCleanupScheduler;
import com.instagram.identity.service.TokenBlacklistService;
import com.instagram.identity.repository.UserRepository;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * This controller contains endpoints that ONLY ADMIN users can access.
 *
 * Access control is configured inside SecurityConfig:
 *    . requestMatchers("/admin/**").hasRole("ADMIN")
 *
 * ✅ IMPROVEMENT: Added monitoring and management endpoints for admins.
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    private final TokenBlacklistService blacklistService;
    private final TokenCleanupScheduler cleanupScheduler;
    private final UserRepository userRepository;

    public AdminController(TokenBlacklistService blacklistService,
                           TokenCleanupScheduler cleanupScheduler,
                           UserRepository userRepository) {
        this.blacklistService = blacklistService;
        this.cleanupScheduler = cleanupScheduler;
        this.userRepository = userRepository;
    }

    /**
     * A simple protected admin endpoint.
     * If you can see this response, your JWT token has ROLE_ADMIN.
     */
    @GetMapping("/dashboard")
    public String adminDashboard() {
        return "Admin Dashboard (Admin role required)";
    }

    /**
     * ✅ NEW: Get system health statistics.
     * Shows current state of authentication system.
     */
    @GetMapping("/stats")
    public Map<String, Object> getSystemStats() {
        Map<String, Object> stats = new HashMap<>();

        // Token statistics
        stats.put("blacklistedTokensCount", blacklistService.getBlacklistSize());

        // User statistics
        stats. put("totalUsers", userRepository.count());

        // System info
        stats.put("serverStatus", "Running");
        stats.put("authenticationMethod", "JWT with RS256");

        return stats;
    }

    /**
     * ✅ NEW: Get detailed blacklist information.
     * Useful for monitoring and debugging token issues.
     */
    @GetMapping("/tokens/blacklist")
    public Map<String, Object> getBlacklistInfo() {
        Map<String, Object> info = new HashMap<>();

        info.put("blacklistedTokensCount", blacklistService.getBlacklistSize());
        info.put("description", "Tokens that have been logged out but not yet expired");
        info.put("cleanupSchedule", "Runs every hour to remove naturally expired tokens");

        return info;
    }

    /**
     * ✅ NEW:  Manually trigger token cleanup.
     * Useful for testing or immediate cleanup without waiting for scheduler.
     */
    @PostMapping("/tokens/cleanup")
    public Map<String, Object> triggerManualCleanup() {
        int sizeBefore = blacklistService.getBlacklistSize();

        // Force cleanup immediately
        cleanupScheduler.forceCleanup();

        int sizeAfter = blacklistService.getBlacklistSize();
        int removed = sizeBefore - sizeAfter;

        Map<String, Object> result = new HashMap<>();
        result.put("message", "Manual cleanup completed");
        result.put("tokensRemoved", removed);
        result.put("remainingTokens", sizeAfter);

        return result;
    }

    /**
     * ✅ NEW: Get all users count by role.
     * Useful for monitoring user distribution.
     */
    @GetMapping("/users/stats")
    public Map<String, Object> getUserStats() {
        Map<String, Object> stats = new HashMap<>();

        long totalUsers = userRepository.count();
        stats.put("totalUsers", totalUsers);
        stats.put("description", "Total registered users in the system");

        return stats;
    }

    /**
     * ✅ NEW: Health check endpoint.
     * Returns 200 OK if admin service is running properly.
     */
    @GetMapping("/health")
    public Map<String, String> healthCheck() {
        Map<String, String> health = new HashMap<>();
        health.put("status", "UP");
        health.put("service", "Admin Controller");
        health.put("message", "All admin endpoints are operational");
        return health;
    }
}