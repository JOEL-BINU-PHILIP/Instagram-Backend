package com.instagram.profile.dto;

import jakarta.validation.constraints.Size;

/**
 * Profile update request
 *
 * Only allows editing:
 *  - fullName
 *  - bio
 *  - profilePictureUrl
 *  - privateAccount
 *
 * Does NOT allow changing:
 *  - username
 *  - userId
 *  - counters
 */
public record UpdateProfileRequest(

        @Size(max = 100, message = "Full name too long")
        String fullName,

        @Size(max = 150, message = "Bio too long")
        String bio,

        @Size(max = 500, message = "URL too long")
        String profilePictureUrl,

        Boolean privateAccount
) {}