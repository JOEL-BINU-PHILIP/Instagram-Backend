package com.instagram.identity.dto;

import java.util.List;

/**
 * This is the response body returned after:
 *  - Login
 *  - Refresh token
 *
 * It contains:
 *  - accessToken: JWT used for authenticated API requests
 *  - refreshToken: long-lived token for requesting new access tokens
 *  - expiresInSeconds: time until the access token expires
 *  - roles: list of roles assigned to the user
 *
 * Using Java Records automatically creates:
 *  - getters
 *  - constructor
 *  - equals/hashCode
 *  - toString
 */
public record AuthResponse(
        String accessToken,
        String refreshToken,
        long expiresInSeconds,
        List<String> roles
) {}
