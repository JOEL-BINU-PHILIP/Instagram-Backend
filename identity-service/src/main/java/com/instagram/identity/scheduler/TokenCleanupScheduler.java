package com.instagram.identity.scheduler;

import com.instagram.identity.service.TokenBlacklistService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype. Component;

/**
 * Automatic cleanup scheduler for expired blacklisted tokens.
 *
 * Why do we need this?
 *  - When tokens are blacklisted, they stay in memory
 *  - After tokens naturally expire, we don't need to track them anymore
 *  - This scheduler removes expired tokens to prevent memory leaks
 *
 * How it works:
 *  - Runs every hour (configurable)
 *  - Calls blacklist service to remove expired tokens
 *  - Logs the cleanup for monitoring
 *
 * NOTE: In production, use Redis with TTL (Time To Live) instead.
 *       Redis automatically removes expired keys, no manual cleanup needed.
 */
@Component
@EnableScheduling
public class TokenCleanupScheduler {

    private static final Logger logger = LoggerFactory.getLogger(TokenCleanupScheduler.class);

    private final TokenBlacklistService blacklistService;

    public TokenCleanupScheduler(TokenBlacklistService blacklistService) {
        this.blacklistService = blacklistService;
    }

    /**
     * Cleanup task that runs every hour.
     *
     * Cron expression breakdown:
     *  - "0"     :  at 0 seconds
     *  - "0"     : at 0 minutes
     *  - "*"     : every hour
     *  - "*"     : every day
     *  - "*"     : every month
     *  - "?"     : any day of the week
     *
     * Alternative schedules:
     *  - Every 30 minutes: @Scheduled(fixedRate = 30 * 60 * 1000)
     *  - Every day at 2 AM: @Scheduled(cron = "0 0 2 * * ?")
     *  - Every 15 minutes: @Scheduled(cron = "0 *15 * * * ? ")
     */
    @Scheduled(cron = "0 0 * * * ? ")  // runs every hour at minute 0
    public void cleanupExpiredTokens() {

        logger.info("Starting automatic cleanup of expired blacklisted tokens.. .");

        int sizeBefore = blacklistService.getBlacklistSize();

        // Remove all expired tokens from the blacklist
        blacklistService.cleanupExpiredTokens();

        int sizeAfter = blacklistService.getBlacklistSize();
        int removed = sizeBefore - sizeAfter;

        logger. info("Cleanup completed. Removed {} expired tokens.  Current blacklist size: {}",
                removed, sizeAfter);
    }

    /**
     * ✅ BONUS: Manual cleanup endpoint (useful for testing).
     * This runs immediately when called.
     */
    public void forceCleanup() {
        logger.info("Manual cleanup triggered");
        blacklistService.cleanupExpiredTokens();
        logger.info("Manual cleanup completed.  Current blacklist size: {}",
                blacklistService.getBlacklistSize());
    }
}