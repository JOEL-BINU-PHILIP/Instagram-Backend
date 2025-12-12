package com.instagram.identity.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * This class represents the login request sent by the client.
 *
 * Example JSON:
 * {
 *   "username": "joel",
 *   "password": "joel123"
 * }
 *
 * @NotBlank ensures both fields must be provided.
 */
public record LoginRequest(
        @NotBlank String username,
        @NotBlank String password
) {}
