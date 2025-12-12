package com.instagram.identity.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * This class simply reads JWT-related settings from application.properties.
 *
 * Instead of hardcoding values (issuer, expiry times, key paths),
 * we inject them using @Value so that everything is configurable.
 */
@Configuration
public class JwtConfig {

    // The "issuer" value that will be placed inside every JWT token.
    @Value("${jwt.issuer}")
    public String issuer;

    // How long access tokens should remain valid (in minutes).
    @Value("${jwt.access-token-validity-minutes}")
    public long accessTokenValidityMinutes;

    // How long refresh tokens should remain valid (in days).
    @Value("${jwt.refresh-token-validity-days}")
    public long refreshTokenValidityDays;

    // Where the private key is stored (used for signing JWTs).
    @Value("${jwt.key-pair.private-key-location}")
    public String privateKeyLocation;

    // Where the public key is stored (used for verifying JWTs).
    @Value("${jwt.key-pair.public-key-location}")
    public String publicKeyLocation;
}
