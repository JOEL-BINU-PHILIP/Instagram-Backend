package com.instagram.post.dto;

import jakarta.validation.constraints. Size;

import java.util.List;

public record UpdatePostRequest(

        @Size(max = 2200, message = "Caption too long")
        String caption,

        String altText,

        LocationDTO location,

        List<String> taggedUserIds,

        Boolean commentsDisabled,

        Boolean hideLikesCount
) {}