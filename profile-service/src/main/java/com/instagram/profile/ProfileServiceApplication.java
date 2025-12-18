package com.instagram.profile;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
/**
 * Responsibilities:
 *  - Store public profile data
 *  - Handle privacy settings
 *  - Verify JWT tokens (READ-ONLY)
 * Does NOT:
 *  - Handle authentication
 *  - Issue or refresh tokens
 *  - Store passwords or roles
 */
@SpringBootApplication
public class ProfileServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(ProfileServiceApplication.class, args);
    }
}