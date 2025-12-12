package com.instagram.identity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * This configuration class creates a PasswordEncoder bean.
 *
 * Spring Security needs a password encoder to hash and verify passwords.
 * BCryptPasswordEncoder is a strong hashing algorithm used in production.
 */
@Configuration
public class PasswordConfig {

    /**
     * Creates and exposes a BCryptPasswordEncoder bean.
     *
     * Whenever any part of the app needs to encode a password,
     * Spring will automatically inject this encoder.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}