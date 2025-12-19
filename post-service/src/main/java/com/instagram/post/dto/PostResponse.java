package com.instagram.post.dto;

import com.instagram.post.model.*;

import java.time.Instant;
import java.util.List;

public record PostResponse(
        String id,
        String userId,
        String username,
        String userProfilePicture,

        PostType type,
        List<Media> mediaItems,
        String caption,
        String altText,

        Location location,
        List<String> taggedUserIds,
        List<String> hashtags,

        Visibility visibility,
        boolean commentsDisabled,
        boolean hideLikesCount,

        long likesCount,
        long commentsCount,
        long sharesCount,
        long savesCount,

        boolean isLikedByViewer,
        boolean isSavedByViewer,

        boolean archived,
        boolean pinned,
        boolean edited,
        Instant editedAt,

        Instant createdAt
) {
    public static PostResponse fromPost(Post post, boolean isLiked, boolean isSaved) {
        return new PostResponse(
                post.getId(),
                post.getUserId(),
                post.getUsername(),
                post.getUserProfilePicture(),
                post.getType(),
                post.getMediaItems(),
                post.getCaption(),
                post.getAltText(),
                post.getLocation(),
                post.getTaggedUserIds(),
                post.getHashtags(),
                post.getVisibility(),
                post.isCommentsDisabled(),
                post.isHideLikesCount(),
                post.getLikesCount(),
                post.getCommentsCount(),
                post.getSharesCount(),
                post.getSavesCount(),
                isLiked,
                isSaved,
                post.isArchived(),
                post.isPinned(),
                post.isEdited(),
                post.getEditedAt(),
                post.getCreatedAt()
        );
    }
}