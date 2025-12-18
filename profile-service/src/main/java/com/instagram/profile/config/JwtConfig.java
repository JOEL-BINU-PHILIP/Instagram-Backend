package com. instagram.profile.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * JWT configuration (verification only)
 *
 * This service does NOT generate tokens.
 * It only VERIFIES tokens using the public key.
 */
@Configuration
public class JwtConfig {

    @Value("${jwt.issuer}")
    public String issuer;

    @Value("${jwt.key-pair.public-key-location}")
    public String publicKeyLocation;
}