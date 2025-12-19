package com.instagram.post.dto;

import com.instagram.post.model. Visibility;
import jakarta.validation. constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;

public record CreatePostRequest(

        @NotNull(message = "Media URLs are required")
        @Size(min = 1, max = 10, message = "Post must have 1-10 media items")
        List<String> mediaUrls,

        @Size(max = 2200, message = "Caption too long")
        String caption,

        String altText,

        LocationDTO location,

        List<String> taggedUserIds,

        List<String> hashtags,

        Visibility visibility,

        Boolean commentsDisabled,

        Boolean hideLikesCount
) {}