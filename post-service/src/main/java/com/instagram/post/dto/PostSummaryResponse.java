package com.instagram.post.dto;

import com.instagram.post.model.Post;

public record PostSummaryResponse(
        String id,
        String thumbnailUrl,
        String type,
        long likesCount,
        long commentsCount,
        boolean isVideo
) {
    public static PostSummaryResponse fromPost(Post post) {
        String thumbnailUrl = post.getMediaItems().isEmpty()
                ? null
                : post.getMediaItems().get(0).getUrl();

        return new PostSummaryResponse(
                post.getId(),
                thumbnailUrl,
                post.getType().name(),
                post.getLikesCount(),
                post.getCommentsCount(),
                post.getType() == com.instagram.post.model.PostType.VIDEO
        );
    }
}