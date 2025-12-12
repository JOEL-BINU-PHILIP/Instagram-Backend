package com.instagram.identity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * This class represents the JSON body required for user registration.
 *
 * Example JSON:
 * {
 *   "username": "joel",
 *   "email": "joel@example.com",
 *   "password": "test123",
 *   "role": "ROLE_BUYER"
 * }
 *
 * Notes:
 *  - @Email ensures the email is valid
 *  - role must be one of: ROLE_ADMIN, ROLE_BUYER, ROLE_SELLER
 */
public record RegisterRequest(
        @NotBlank String username,
        @NotBlank @Email String email,
        @NotBlank String password,
        @NotBlank String role
) {}
