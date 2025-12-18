package com.instagram.identity.scheduler;

import com.instagram.identity.service.RefreshTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Automatic cleanup of expired refresh tokens.
 * Runs daily at 3 AM.
 */
@Component
public class RefreshTokenCleanupScheduler {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenCleanupScheduler.class);

    private final RefreshTokenService refreshTokenService;

    public RefreshTokenCleanupScheduler(RefreshTokenService refreshTokenService) {
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * Run every day at 3:00 AM.
     * Cron:  "0 0 3 * * ?" = second minute hour day month weekday
     */
    @Scheduled(cron = "0 0 3 * * ? ")
    public void cleanupExpiredTokens() {
        logger.info("Starting refresh token cleanup...");

        try {
            refreshTokenService.cleanupExpiredTokens();
            logger.info("Refresh token cleanup completed successfully");
        } catch (Exception e) {
            logger.error("Error during refresh token cleanup", e);
        }
    }
}