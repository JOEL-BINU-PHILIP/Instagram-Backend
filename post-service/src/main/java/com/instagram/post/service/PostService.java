package com.instagram.post.service;

import com.instagram.post.dto.*;
import com.instagram.post.exception.PostNotFoundException;
import com. instagram.post.exception.UnauthorizedAccessException;
import com.instagram. post.model.*;
import com.instagram.post. repository.PostRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework. data.domain.Pageable;
import org.springframework.data. domain.Sort;
import org. springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time. Instant;
import java.util. List;
import java.util. stream.Collectors;

@Service
public class PostService {

    private final PostRepository postRepository;
    private final LikeService likeService;
    private final SaveService saveService;

    public PostService(PostRepository postRepository,
                       LikeService likeService,
                       SaveService saveService) {
        this.postRepository = postRepository;
        this.likeService = likeService;
        this.saveService = saveService;
    }

    @Transactional
    public PostResponse createPost(String userId,
                                   String username,
                                   CreatePostRequest request) {

        Post post = new Post();
        post.setUserId(userId);
        post.setUsername(username);

        // Determine post type
        if (request.mediaUrls().size() == 1) {
            String url = request.mediaUrls().get(0);
            post.setType(isVideo(url) ? PostType.VIDEO : PostType.IMAGE);
        } else {
            post.setType(PostType. CAROUSEL);
        }

        // Set media items
        List<Media> mediaItems = request.mediaUrls().stream()
                .map(url -> {
                    Media media = new Media();
                    media.setUrl(url);
                    media.setMediaType(isVideo(url) ? "video" : "image");
                    return media;
                })
                .collect(Collectors.toList());
        post.setMediaItems(mediaItems);

        // Set content
        post.setCaption(request.caption());
        post.setAltText(request.altText());

        // Set location
        if (request.location() != null) {
            Location location = new Location();
            location.setName(request.location().name());
            location.setLatitude(request.location().latitude());
            location.setLongitude(request.location().longitude());
            post.setLocation(location);
        }

        // Set tags
        if (request. taggedUserIds() != null) {
            post.setTaggedUserIds(request.taggedUserIds());
        }

        if (request.hashtags() != null) {
            post.setHashtags(request.hashtags());
        }

        // Set privacy
        post.setVisibility(request.visibility() != null ? request.visibility() : Visibility.PUBLIC);
        post.setCommentsDisabled(request. commentsDisabled() != null && request.commentsDisabled());
        post.setHideLikesCount(request.hideLikesCount() != null && request.hideLikesCount());

        Post saved = postRepository.save(post);

        return PostResponse.fromPost(saved, false, false);
    }

    public PostResponse getPostById(String postId, String viewerId) {
        Post post = postRepository.findByIdAndDeletedFalse(postId)
                .orElseThrow(() -> new PostNotFoundException("Post not found"));

        boolean isFollowing = true; // TODO: Check follow service

        if (! post.isViewableBy(viewerId, isFollowing)) {
            throw new UnauthorizedAccessException("Cannot view this post");
        }

        boolean isLiked = likeService. isPostLikedByUser(postId, viewerId);
        boolean isSaved = saveService.isPostSavedByUser(postId, viewerId);

        return PostResponse.fromPost(post, isLiked, isSaved);
    }

    public Page<PostSummaryResponse> getUserPosts(String username,
                                                  String viewerId,
                                                  int page,
                                                  int size) {
        String userId = username; // TODO: Get userId from Profile Service

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

        Page<Post> posts = postRepository.findByUserIdAndDeletedFalseAndArchivedFalse(
                userId,
                pageable
        );

        return posts.map(PostSummaryResponse::fromPost);
    }

    @Transactional
    public PostResponse updatePost(String postId,
                                   String userId,
                                   UpdatePostRequest request) {

        Post post = postRepository.findByIdAndDeletedFalse(postId)
                .orElseThrow(() -> new PostNotFoundException("Post not found"));

        if (!post.isOwner(userId)) {
            throw new UnauthorizedAccessException("Not authorized to edit this post");
        }

        if (request.caption() != null) {
            post.setCaption(request.caption());
            post.setEdited(true);
            post.setEditedAt(Instant.now());
        }

        if (request.altText() != null) {
            post.setAltText(request.altText());
        }

        if (request.location() != null) {
            Location location = new Location();
            location.setName(request. location().name());
            location. setLatitude(request.location().latitude());
            location.setLongitude(request.location().longitude());
            post.setLocation(location);
        }

        if (request.taggedUserIds() != null) {
            post.setTaggedUserIds(request.taggedUserIds());
        }

        if (request.commentsDisabled() != null) {
            post.setCommentsDisabled(request.commentsDisabled());
        }

        if (request.hideLikesCount() != null) {
            post.setHideLikesCount(request.hideLikesCount());
        }

        post.setUpdatedAt(Instant.now());
        Post updated = postRepository.save(post);

        boolean isLiked = likeService.isPostLikedByUser(postId, userId);
        boolean isSaved = saveService. isPostSavedByUser(postId, userId);

        return PostResponse.fromPost(updated, isLiked, isSaved);
    }

    @Transactional
    public void deletePost(String postId, String userId) {
        Post post = postRepository.findByIdAndDeletedFalse(postId)
                .orElseThrow(() -> new PostNotFoundException("Post not found"));

        if (! post.isOwner(userId)) {
            throw new UnauthorizedAccessException("Not authorized to delete this post");
        }

        post.setDeleted(true);
        post.setDeletedAt(Instant.now());
        postRepository.save(post);
    }

    @Transactional
    public void archivePost(String postId, String userId) {
        Post post = postRepository.findByIdAndDeletedFalse(postId)
                .orElseThrow(() -> new PostNotFoundException("Post not found"));

        if (! post.isOwner(userId)) {
            throw new UnauthorizedAccessException("Not authorized");
        }

        post.setArchived(true);
        postRepository.save(post);
    }

    @Transactional
    public void unarchivePost(String postId, String userId) {
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new PostNotFoundException("Post not found"));

        if (!post.isOwner(userId)) {
            throw new UnauthorizedAccessException("Not authorized");
        }

        post.setArchived(false);
        postRepository.save(post);
    }

    @Transactional
    public void pinPost(String postId, String userId) {
        long pinnedCount = postRepository.countByUserIdAndPinnedTrueAndDeletedFalse(userId);
        if (pinnedCount >= 3) {
            throw new RuntimeException("Maximum 3 posts can be pinned");
        }

        Post post = postRepository.findByIdAndDeletedFalse(postId)
                .orElseThrow(() -> new PostNotFoundException("Post not found"));

        if (!post.isOwner(userId)) {
            throw new UnauthorizedAccessException("Not authorized");
        }

        post.setPinned(true);
        postRepository.save(post);
    }

    @Transactional
    public void unpinPost(String postId, String userId) {
        Post post = postRepository.findByIdAndDeletedFalse(postId)
                .orElseThrow(() -> new PostNotFoundException("Post not found"));

        if (!post.isOwner(userId)) {
            throw new UnauthorizedAccessException("Not authorized");
        }

        post.setPinned(false);
        postRepository.save(post);
    }

    private boolean isVideo(String url) {
        return url. toLowerCase().matches(".*\\.(mp4|mov|avi|mkv)$");
    }
}