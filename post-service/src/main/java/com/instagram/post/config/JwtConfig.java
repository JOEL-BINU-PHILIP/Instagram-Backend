package com.instagram.post.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    @Value("${jwt.issuer}")
    public String issuer;

    @Value("${jwt.key-pair.public-key-location}")
    public String publicKeyLocation;
}