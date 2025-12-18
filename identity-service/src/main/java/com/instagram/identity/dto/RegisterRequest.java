package com.instagram.identity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * ✅ INSTAGRAM-STYLE Registration Request
 *
 * Changes from original:
 *  - NO role field (always ROLE_USER)
 *  - Optional accountType (defaults to PERSONAL)
 *  - Username validation (alphanumeric + dots/underscores)
 *  - Full name required
 */
public record RegisterRequest(

        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 30, message = "Username must be 3-30 characters")
        @Pattern(regexp = "^[a-zA-Z0-9._]+$", message = "Username can only contain letters, numbers, dots, and underscores")
        String username,

        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, message = "Password must be at least 8 characters")
        String password,

        @NotBlank(message = "Full name is required")
        @Size(max = 100, message = "Full name too long")
        String fullName,

        /**
         * Optional: Account type selection during registration.
         * Default: PERSONAL
         *
         * Users can switch later in settings.
         */
        String accountType  // PERSONAL, CREATOR, or BUSINESS (validated in service)
) {}